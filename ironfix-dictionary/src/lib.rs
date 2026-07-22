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
//!   ([`Dictionary::from_quickfix_xml`]) with a component-recursion depth guard
//! - **Runtime validation**: message validation against dictionary rules
//!   ([`Validator`]) — known message type, defined and allowed tags, required
//!   fields, enum values, repeating-group count and delimiter
//! - **Embedded dictionary**: the standard FIX 4.4 specification
//!   ([`Dictionary::fix44`]), vendored from QuickFIX under its license
//!
//! ## Current limitations
//!
//! **FIX 4.4 is the only embedded dictionary.** Every other version — 4.0
//! through 4.3, and 5.0 through 5.0 SP2 / FIXT.1.1 — requires you to supply the
//! QuickFIX XML yourself via [`Dictionary::from_quickfix_xml`]; the [`Version`]
//! enum naming a version does not imply a bundled schema for it.
//!
//! **[`Validator`] is opt-in and is never invoked automatically.** Neither
//! `ironfix-engine` nor `ironfix-transport` validates against a dictionary — a
//! message that decodes successfully has not been schema-checked unless you
//! call the validator yourself.

pub mod loader;
pub mod schema;
pub mod validator;

pub use loader::DictionaryError;
pub use schema::{
    ComponentDef, Dictionary, FieldDef, FieldRef, FieldType, GroupDef, MessageCategory, MessageDef,
    Version,
};
pub use validator::{ValidationError, Validator};
