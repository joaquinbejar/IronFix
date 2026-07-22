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

use ironfix_codegen::{CodeGenerator, GeneratorConfig};
use ironfix_dictionary::schema::{
    ComponentDef, ComponentRef, Dictionary, FieldDef, FieldRef as SchemaFieldRef, FieldType,
    GroupDef, MessageCategory, MessageDef, Version,
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

    dict.add_component(ComponentDef {
        name: "Instrument".to_string(),
        fields: vec![field_ref(55, "Symbol", true)],
        groups: Vec::new(),
        components: Vec::new(),
    });

    dict.add_message(MessageDef {
        msg_type: "D".to_string(),
        name: "NewOrderSingle".to_string(),
        category: MessageCategory::App,
        fields: vec![
            field_ref(11, "ClOrdID", true),
            field_ref(12, "ClOrdId", false),
            field_ref(34, "MsgSeqNum", false),
            field_ref(43, "PossDupFlag", false),
            field_ref(44, "Price", false),
            field_ref(54, "Side", true),
            field_ref(96, "RawData", false),
            field_ref(236, "Yield", false),
        ],
        groups: vec![GroupDef {
            count_tag: 453,
            name: "NoPartyIDs".to_string(),
            delimiter_tag: 448,
            fields: vec![field_ref(448, "PartyID", true)],
            groups: vec![GroupDef {
                count_tag: 802,
                name: "NoPartySubIDs".to_string(),
                delimiter_tag: 523,
                fields: vec![field_ref(523, "PartySubID", true)],
                groups: Vec::new(),
                components: Vec::new(),
                required: false,
            }],
            components: Vec::new(),
            required: false,
        }],
        components: vec![ComponentRef::new("Instrument", false)],
    });

    // A message with no fields at all: the generated struct must still be
    // valid Rust.
    dict.add_message(MessageDef {
        msg_type: "0".to_string(),
        name: "Heartbeat".to_string(),
        category: MessageCategory::Admin,
        fields: Vec::new(),
        groups: Vec::new(),
        components: Vec::new(),
    });

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
