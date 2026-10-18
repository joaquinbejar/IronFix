/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! The fixture dictionary shared by the generated-code tests.
//!
//! Small on purpose, but it carries every shape the generator has to get
//! right: a required field, an optional field, a decimal field, a `Data`
//! field, a field name that is a Rust keyword (`Yield` -> `r#yield`), two
//! field names that collapse onto one identifier, a component-contributed
//! field, a repeating group, a group nested inside a group, and a message with
//! no fields at all.
//!
//! Alongside it, two of the embedded QuickFIX dictionaries are generated in
//! full: FIX 4.2 and FIXT 1.1. FIX 5.0 SP2 is deliberately not among them:
//! its generated source is roughly 50 MB, too large to commit as a golden
//! file or to compile in CI.

use ironfix_codegen::{CodeGenerator, GeneratorConfig};
use ironfix_dictionary::DictionaryError;
use ironfix_dictionary::schema::{
    ComponentDef, ComponentRef, Dictionary, FieldDef, FieldRef as SchemaFieldRef, FieldType,
    GroupDef, Member, MessageCategory, MessageDef, Version,
};

/// Builds a field reference for the fixture dictionary.
fn field_ref(tag: u32, name: &str, required: bool) -> SchemaFieldRef {
    SchemaFieldRef {
        tag,
        name: name.to_string(),
        required,
    }
}

/// A hand-built dictionary covering every shape the generator handles.
fn sample_dictionary() -> Dictionary {
    let mut dict = Dictionary::new(Version::Fix44);

    for (tag, name, field_type) in [
        (11u32, "ClOrdID", FieldType::String),
        // Collapses onto the same identifier as ClOrdID (11).
        (12, "ClOrdId", FieldType::String),
        (34, "MsgSeqNum", FieldType::SeqNum),
        (43, "PossDupFlag", FieldType::Boolean),
        (44, "Price", FieldType::Price),
        (54, "Side", FieldType::Char),
        (55, "Symbol", FieldType::String),
        (96, "RawData", FieldType::Data),
        // Lowercases to the reserved keyword `yield`.
        (236, "Yield", FieldType::Percentage),
        (448, "PartyID", FieldType::String),
        (453, "NoPartyIDs", FieldType::NumInGroup),
        (523, "PartySubID", FieldType::String),
        (802, "NoPartySubIDs", FieldType::NumInGroup),
    ] {
        dict.add_field(FieldDef::new(tag, name, field_type));
    }

    dict.add_component(ComponentDef::new(
        "Instrument",
        vec![Member::Field(field_ref(55, "Symbol", true))],
    ));

    dict.add_message(MessageDef::new(
        "D",
        "NewOrderSingle",
        MessageCategory::App,
        vec![
            Member::Field(field_ref(11, "ClOrdID", true)),
            Member::Field(field_ref(12, "ClOrdId", false)),
            Member::Field(field_ref(34, "MsgSeqNum", false)),
            Member::Field(field_ref(43, "PossDupFlag", false)),
            Member::Field(field_ref(44, "Price", false)),
            Member::Field(field_ref(54, "Side", true)),
            Member::Field(field_ref(96, "RawData", false)),
            Member::Field(field_ref(236, "Yield", false)),
            Member::Group(GroupDef::new(
                453,
                "NoPartyIDs",
                448,
                false,
                vec![
                    Member::Field(field_ref(448, "PartyID", true)),
                    Member::Group(GroupDef::new(
                        802,
                        "NoPartySubIDs",
                        523,
                        false,
                        vec![Member::Field(field_ref(523, "PartySubID", true))],
                    )),
                ],
            )),
            Member::Component(ComponentRef::new("Instrument", false)),
        ],
    ));

    // A message with no fields at all: the generated struct must still be
    // valid Rust.
    dict.add_message(MessageDef::new(
        "0",
        "Heartbeat",
        MessageCategory::Admin,
        Vec::new(),
    ));

    dict
}

/// Generates from the sample dictionary, failing the test on a generator
/// error rather than unwrapping.
#[track_caller]
pub fn generate_sample() -> String {
    let generator = CodeGenerator::with_config(GeneratorConfig::default());
    match generator.generate(&sample_dictionary()) {
        Ok(code) => code,
        Err(err) => panic!("the sample dictionary must generate: {err}"),
    }
}

/// Generates from an embedded dictionary, failing the test on a load or a
/// generator error rather than unwrapping.
#[track_caller]
fn generate_embedded(loaded: Result<&'static Dictionary, DictionaryError>, what: &str) -> String {
    let dict = match loaded {
        Ok(dict) => dict,
        Err(err) => panic!("the embedded {what} dictionary must load: {err}"),
    };
    let generator = CodeGenerator::with_config(GeneratorConfig::default());
    match generator.generate(dict) {
        Ok(code) => code,
        Err(err) => panic!("the embedded {what} dictionary must generate: {err}"),
    }
}

/// Generates from the embedded FIX 4.2 dictionary (`golden/fix42.rs`).
#[track_caller]
pub fn generate_fix42() -> String {
    generate_embedded(Dictionary::fix42(), "FIX 4.2")
}

/// Generates from the embedded FIXT 1.1 dictionary (`golden/fixt11.rs`).
#[track_caller]
pub fn generate_fixt11() -> String {
    generate_embedded(Dictionary::fixt11(), "FIXT 1.1")
}
