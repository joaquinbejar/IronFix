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
//!   definitions ([`schema`])
//! - **Dictionary parsing**: a QuickFIX XML loader
//!   ([`Dictionary::from_quickfix_xml`]) with a component-recursion depth guard.
//!   Loading is treated as untrusted-input parsing: see the [`loader`] module
//!   docs for the ceilings that bound it.
//! - **Runtime validation**: message validation against dictionary rules
//!   ([`Validator`]): known message type, defined and allowed tags, required
//!   fields, enum values, repeating-group count and delimiter
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
//!   a FIXT.1.1 transport dictionary with a FIX 5.0 family application
//!   dictionary, and [`Validator::for_session`] validates against the pair
//!   (header and trailer from the transport side, body from the application
//!   side, admin messages entirely from the transport side)
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
//! **[`SessionDictionary`] does not read `ApplVerID(1128)`.** The caller picks
//! the application dictionary when building the pair; a message whose
//! `ApplVerID` names a different application version is still validated
//! against that one.
//!
//! **[`Validator`] is opt-in and is never invoked automatically.** Neither
//! `ironfix-engine` nor `ironfix-transport` validates against a dictionary; a
//! message that decodes successfully has not been schema-checked unless you
//! call the validator yourself.
//!
//! [`ironfix_dictionary::schema::FieldRef`](FieldRef) is the schema's
//! *reference to a field definition*, not
//! `ironfix_core::field::FieldRef`, which is a field borrowed from a decoded
//! buffer. Both names exist in the workspace; always qualify them.

pub mod composition;
pub mod loader;
pub mod schema;
pub mod validator;

pub use composition::SessionDictionary;
pub use loader::{DefinitionKind, DictionaryError, MAX_COMPONENT_DEPTH, MAX_NESTING_DEPTH};
pub use schema::{
    ComponentDef, ComponentRef, Dictionary, FieldDef, FieldRef, FieldType, GroupDef,
    MessageCategory, MessageDef, UnknownFieldType, Version,
};
pub use validator::{MAX_SCOPE_DEPTH, MAX_SCOPE_NODES, ValidationError, Validator};
