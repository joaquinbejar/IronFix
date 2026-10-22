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
//! - **Embedded dictionaries**: four QuickFIX specifications vendored verbatim
//!   under the QuickFIX Software License, Version 1.0 (see
//!   `spec/LICENSE-QUICKFIX` and `spec/README.md`):
//!
//!   | Constructor | Version | Role |
//!   |---|---|---|
//!   | [`Dictionary::fix42`] | FIX 4.2 | complete (header, trailer, all messages) |
//!   | [`Dictionary::fix44`] | FIX 4.4 | complete (header, trailer, all messages) |
//!   | [`Dictionary::fixt11`] | FIXT 1.1 | transport (header, trailer, admin messages) |
//!   | [`Dictionary::fix50sp2`] | FIX 5.0 SP2 | application (messages only) |
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
//! This product includes software developed by quickfixengine.org
//! (<http://www.quickfixengine.org/>).
//!
//! ## Current limitations
//!
//! **Only FIX 4.2, FIX 4.4, FIXT 1.1 and FIX 5.0 SP2 are embedded.** FIX 4.0,
//! 4.1, 4.3, 5.0 and 5.0 SP1 require you to supply the QuickFIX XML yourself
//! via [`Dictionary::from_quickfix_xml`]; the [`Version`] enum naming a version
//! does not imply a bundled schema for it.
//!
//! **Orchestra loading is tested on the four embedded versions only.** The
//! Orchestra repositories the tests load are the FIX Trading Community's FIX
//! 4.2, FIX 4.4, FIXT session layer and FIX Latest ones, test fixtures that
//! are neither embedded nor published; FIX 5.0 SP2 is derived from FIX
//! Latest by pedigree with [`Dictionary::from_orchestra_latest_xml`]. Each
//! is diffed against the embedded QuickFIX dictionary of its version, and
//! every difference is listed in
//! [`doc/orchestra_differences.md`](https://github.com/joaquinbejar/IronFix/blob/main/doc/orchestra_differences.md)
//! (Orchestra wins on a conflict). [`Dictionary::from_orchestra_xml`]
//! rejects `FIX.Latest` repositories with
//! [`DictionaryError::UnsupportedVersion`], because FIX Latest names no
//! fixed FIX version; only the targeted import reads them. A repository
//! named `FIXT` must declare `FIXT.1.1`, or be the FIXT session layer
//! published under a FIX 5.0 SP2 extension pack (the FIX Trading
//! Community's declares `FIX.5.0SP2_EP247`), which loads as FIXT 1.1; see
//! the [`orchestra`] module docs for the rule.
//!
//! **[`SessionDictionary`] does not read `ApplVerID(1128)`.** The caller picks
//! the application dictionary when building the pair; a message whose
//! `ApplVerID` names a different application version is still validated
//! against that one.
//!
//! **The embedded FIXT 1.1 dictionary deviates from FIXT 1.1 upstream.** The
//! vendored QuickFIX `FIXT11.xml` defines the Logon `MsgTypeGrp` component
//! with no members and does not define `NoMsgTypes(384)` or
//! `MsgDirection(385)`, where FIXT 1.1 defines the `NoMsgTypes` group
//! (`372`, `385`, `1130`, `1406`, `1131`, `1410`). A Logon carrying the group
//! is therefore reported as invalid against [`Dictionary::fixt11`]. The file
//! stays unpatched; to accept the group, load a FIXT 1.1 dictionary that
//! defines it with [`Dictionary::from_quickfix_xml`] and compose that.
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
