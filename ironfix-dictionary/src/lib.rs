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
//! - **Schema definitions**: Field, message, and component definitions
//! - **Dictionary parsing**: QuickFIX XML format parser ([`Dictionary::from_quickfix_xml`])
//! - **Runtime validation**: Message validation against dictionary rules ([`Validator`])
//! - **Embedded dictionaries**: Pre-loaded standard FIX 4.4 specification ([`Dictionary::fix44`])

pub mod loader;
pub mod schema;
pub mod validator;

pub use loader::DictionaryError;
pub use schema::{
    ComponentDef, Dictionary, FieldDef, FieldRef, FieldType, GroupDef, MessageCategory, MessageDef,
    Version,
};
pub use validator::{ValidationError, Validator};
