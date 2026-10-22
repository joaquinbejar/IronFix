/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Dictionary
//!
//! FIX specification parsing and dictionary management for the IronFix engine.
//!
//! This crate provides:
//! - **Schema definitions**: field, message, component and repeating-group
//!   definitions ([`schema`]). Messages, components and groups keep their
//!   members per kind and also in the order the XML lists them
//!   ([`GroupDef::members`]), the order FIX requires inside a repeating group
//! - **Dictionary parsing**: a QuickFIX XML loader
//!   ([`Dictionary::from_quickfix_xml`]) with a component-recursion depth guard.
//!   Loading is treated as untrusted-input parsing: see the [`loader`] module
//!   docs for the ceilings that bound it.
//! - **FIX Orchestra loading**: [`Dictionary::from_orchestra_xml`] reads the
//!   `base` scenario of a FIX Orchestra 1.0 repository into the same model,
//!   and returns an [`OrchestraReport`] of what the model cannot hold; see the
//!   [`orchestra`] module docs for the mapping and the limits.
//! - **Runtime validation**: message validation against dictionary rules
//!   ([`Validator`]): known message type, defined and allowed tags, required
//!   fields, enum values, repeating-group count and delimiter, and the
//!   required members of every group entry
//! - **Embedded dictionaries**: four FIX Trading Community FIX Orchestra
//!   repositories vendored verbatim under the Apache License, Version 2.0
//!   (see `spec/orchestra/LICENSE` and `spec/orchestra/README.md`); the
//!   crate ships no QuickFIX file:
//!
//!   | Constructor | Version | Source | Role |
//!   |---|---|---|---|
//!   | [`Dictionary::fix42`] | FIX 4.2 | `OrchestraFIX42.xml` | complete (header, trailer, all messages) |
//!   | [`Dictionary::fix44`] | FIX 4.4 | `OrchestraFIX44.xml` | complete (header, trailer, all messages) |
//!   | [`Dictionary::fixt11`] | FIXT 1.1 | `FIXTSession.xml` | transport (header, trailer, admin messages) |
//!   | [`Dictionary::fix50sp2`] | FIX 5.0 SP2 | `OrchestraFIXLatest.xml`, filtered to FIX 5.0 SP2 | complete (header, trailer, session and application messages) |
//!
//!   Up to 0.5 these were QuickFIX files; the differences users may observe
//!   are listed in
//!   [`doc/orchestra_differences.md`](https://github.com/joaquinbejar/IronFix/blob/main/doc/orchestra_differences.md).
//!
//! - **Transport plus application composition**: [`SessionDictionary`] pairs
//!   a FIXT.1.1 transport dictionary with an application dictionary of any
//!   version FIXT.1.1 carries (FIX 4.0 through 5.0 SP2), and
//!   [`Validator::for_session`] validates against the pair with
//!   QuickFIX-like semantics: `BeginString(8)` must be `FIXT.1.1`, header
//!   and trailer come from the transport side, the body from the application
//!   side, and admin messages entirely from the transport side (see the
//!   [`validator`] module docs for the differences from QuickFIX)
//! - **Repeating-group reader** ([`group`]): a [`MessageLayout`] built once
//!   per message type from a dictionary (or [`GroupSpec`] / [`GroupSet`]
//!   tables built at compile time) reads a decoded message's groups as
//!   borrowed views: [`GroupEntries`] yields one [`GroupEntry`] per entry,
//!   with own-level field lookup and nested groups, and [`GroupSet::field`]
//!   finds a message-level field outside every group. The whole group is
//!   checked up front with the validator's own positional walk, so a
//!   malformed group is a [`GroupError`], never a partial view. A successful
//!   read, and one that fails with a structural error, allocate nothing for
//!   groups of up to 512 entry-level members (every embedded group); see the
//!   [`group`] module docs for the error paths that do
//!
//! ## Current limitations
//!
//! **Only FIX 4.2, FIX 4.4, FIXT 1.1 and FIX 5.0 SP2 are embedded.** FIX 4.0,
//! 4.1, 4.3, 5.0 and 5.0 SP1 require you to supply the XML yourself, a
//! QuickFIX file via [`Dictionary::from_quickfix_xml`] or an Orchestra
//! repository via [`Dictionary::from_orchestra_xml`]; the [`Version`] enum
//! naming a version does not imply a bundled schema for it.
//!
//! **Orchestra loading is tested on the four embedded versions only.** The
//! repositories the tests load are the embedded ones. Each was diffed
//! against the QuickFIX dictionary of its version the crate embedded up to
//! 0.5 (kept as a test fixture, not published), and every difference is
//! listed in
//! [`doc/orchestra_differences.md`](https://github.com/joaquinbejar/IronFix/blob/main/doc/orchestra_differences.md)
//! (Orchestra wins on a conflict). [`Dictionary::from_orchestra_xml`]
//! rejects `FIX.Latest` repositories with
//! [`DictionaryError::UnsupportedVersion`], because FIX Latest names no
//! fixed FIX version; only [`Dictionary::from_orchestra_latest_xml`] reads
//! them, and only as FIX 5.0 SP2. A repository named `FIXT` must declare
//! `FIXT.1.1`, or be the FIXT session layer published under a FIX 5.0 SP2
//! extension pack (the FIX Trading Community's declares
//! `FIX.5.0SP2_EP247`), which loads as FIXT 1.1; see the [`orchestra`]
//! module docs for the rule.
//!
//! **The embedded FIX 5.0 SP2 dictionary keeps the latest form of each
//! element.** It is derived from FIX Latest by pedigree (what was added at
//! or before FIX 5.0 SP2 and not deprecated by then); an element changed
//! after FIX 5.0 SP2 keeps its FIX Latest form.
//!
//! **[`SessionDictionary`] does not read `ApplVerID(1128)`.** The caller picks
//! the application dictionary when building the pair; a message whose
//! `ApplVerID` names a different application version is still validated
//! against that one.
//!
//! **[`Validator::new`] does not check `BeginString(8)`**; only
//! [`Validator::for_session`] does.
//!
//! **[`Validator`] is opt-in.** `ironfix-transport` never validates. The
//! engine validates inbound application messages only when a session is
//! given an [`InboundValidator`](ironfix_core::InboundValidator) (which
//! [`Validator`], [`Dictionary`] and [`SessionDictionary`] implement) with a
//! policy other than `Off`; administrative messages are never checked
//! against the dictionary there (ADR-0031). Otherwise a message that decodes
//! successfully has not been schema-checked unless you call the validator
//! yourself.
//!
//! [`ironfix_dictionary::schema::FieldRef`](FieldRef) is the schema's
//! *reference to a field definition*, not
//! `ironfix_core::field::FieldRef`, which is a field borrowed from a decoded
//! buffer. Both names exist in the workspace; always qualify them.

pub mod composition;
mod document;
pub mod group;
pub mod loader;
pub mod orchestra;
pub mod schema;
mod scope;
pub mod validator;
mod walk;

pub use composition::SessionDictionary;
pub use group::{
    GroupEntries, GroupEntry, GroupError, GroupSet, GroupSpec, MessageLayout, SpecError,
};
pub use loader::{DefinitionKind, DictionaryError, MAX_COMPONENT_DEPTH, MAX_NESTING_DEPTH};
pub use orchestra::{
    MAX_ORCHESTRA_ATTRIBUTES_LEN, MAX_ORCHESTRA_DOCUMENT_LEN, MAX_ORCHESTRA_FIELD_VALUES,
    MAX_ORCHESTRA_MEMBERS, MAX_ORCHESTRA_NAME_LEN, MAX_ORCHESTRA_REPORT_ENTRIES,
    ORCHESTRA_NAMESPACE, OrchestraImport, OrchestraKind, OrchestraReport, UnmappedConstruct,
};
pub use schema::{
    ComponentDef, ComponentRef, Dictionary, FieldDef, FieldRef, FieldType, GroupDef, Member,
    MemberRef, MessageCategory, MessageDef, UnknownFieldType, Version,
};
pub use validator::{
    MAX_SCOPE_DEPTH, MAX_SCOPE_NODES, MAX_VALIDATION_ERRORS, ValidationError, Validator,
};
