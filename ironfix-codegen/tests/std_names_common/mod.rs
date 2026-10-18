/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! A dictionary whose fields and messages are named after standard library
//! items, `Vec`, `String`, `Option` and `Result`, for the golden files
//! `golden/std_names.rs` (`CodeGenerator::generate`) and
//! `golden/views_std_names.rs` (`CodeGenerator::generate_views`).
//!
//! A field with declared values becomes an enumeration of its name in the
//! generated `enums` module, and a message a struct of its name in the
//! default output's `messages` module, and a component a struct of its name
//! in its `components` module. Generated code that named a standard item by
//! its bare name there (a multi-value field's `join` returning `Vec<u8>`, an
//! optional `String` field) would resolve to the generated type and not
//! compile. The components `Vec` and `String` also share their names with
//! messages, which the default output keeps apart in its two modules.

use ironfix_codegen::CodeGenerator;
use ironfix_dictionary::schema::{
    ComponentDef, ComponentRef, Dictionary, FieldDef, FieldRef as SchemaFieldRef, FieldType,
    GroupDef, Member, MessageCategory, MessageDef, Version,
};
use std::collections::HashMap;

/// Builds a field reference.
fn field_ref(tag: u32, name: &str, required: bool) -> SchemaFieldRef {
    SchemaFieldRef {
        tag,
        name: name.to_string(),
        required,
    }
}

/// Builds a value table from `(wire value, description)` pairs.
fn values(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(value, description)| (value.to_string(), description.to_string()))
        .collect()
}

/// The dictionary: four enumerations and four messages named after
/// standard library items, a multi-value enumeration (whose `join` builds a
/// `Vec`), a `String` field, a LENGTH/DATA pair (a `Vec<u8>` in the default
/// output), a repeating group (a `Vec` of entries), and two components
/// named `Vec` and `String`, like two of the messages: `String` holds
/// `Vec`, the message `Vec` lists the component `Vec` (optional) and the
/// message `String` the component `String` (required).
#[must_use]
pub fn std_names_dictionary() -> Dictionary {
    let mut dict = Dictionary::new(Version::Fix44);
    dict.add_field(
        FieldDef::new(5001, "Vec", FieldType::Char)
            .with_values(values(&[("A", "ALPHA"), ("B", "BRAVO")])),
    );
    dict.add_field(
        FieldDef::new(5002, "String", FieldType::String).with_values(values(&[("X", "X_RAY")])),
    );
    dict.add_field(
        FieldDef::new(5003, "Option", FieldType::Int).with_values(values(&[("1", "ONE")])),
    );
    dict.add_field(
        FieldDef::new(5004, "Result", FieldType::Char).with_values(values(&[("Y", "YES")])),
    );
    dict.add_field(
        FieldDef::new(5005, "Flags", FieldType::MultipleCharValue)
            .with_values(values(&[("A", "ALPHA"), ("B", "BRAVO")])),
    );
    dict.add_field(FieldDef::new(5006, "Text", FieldType::String));
    dict.add_field(FieldDef::new(95, "RawDataLength", FieldType::Length));
    dict.add_field(FieldDef::new(96, "RawData", FieldType::Data));
    dict.add_field(FieldDef::new(5009, "NoItems", FieldType::NumInGroup));
    dict.add_field(FieldDef::new(5010, "ItemName", FieldType::String));

    dict.add_message(MessageDef::new(
        "U1",
        "Option",
        MessageCategory::App,
        vec![
            Member::Field(field_ref(5001, "Vec", true)),
            Member::Field(field_ref(5002, "String", false)),
            Member::Field(field_ref(5003, "Option", false)),
            Member::Field(field_ref(5004, "Result", false)),
            Member::Field(field_ref(5005, "Flags", false)),
            Member::Field(field_ref(5006, "Text", false)),
            Member::Field(field_ref(95, "RawDataLength", false)),
            Member::Field(field_ref(96, "RawData", false)),
            Member::Group(GroupDef::new(
                5009,
                "NoItems",
                5010,
                false,
                vec![Member::Field(field_ref(5010, "ItemName", true))],
            )),
        ],
    ));
    dict.add_field(FieldDef::new(5011, "Note", FieldType::String));
    dict.add_component(ComponentDef::new(
        "Vec",
        vec![Member::Field(field_ref(5011, "Note", true))],
    ));
    dict.add_component(ComponentDef::new(
        "String",
        vec![Member::Component(ComponentRef::new("Vec", false))],
    ));
    for (msg_type, name, component) in [
        ("U2", "Vec", Some(ComponentRef::new("Vec", false))),
        ("U3", "String", Some(ComponentRef::new("String", true))),
        ("U4", "Result", None),
    ] {
        let text = Member::Field(field_ref(5006, "Text", false));
        dict.add_message(MessageDef::new(
            msg_type,
            name,
            MessageCategory::App,
            std::iter::once(text).chain(component.map(Member::Component)),
        ));
    }
    dict
}

/// Generates the default output of [`std_names_dictionary`]
/// (`golden/std_names.rs`).
#[track_caller]
#[must_use]
pub fn generate_std_names() -> String {
    match CodeGenerator::new().generate(&std_names_dictionary()) {
        Ok(code) => code,
        Err(err) => panic!("the standard-names dictionary must generate: {err}"),
    }
}

/// Generates the views of [`std_names_dictionary`]
/// (`golden/views_std_names.rs`).
#[track_caller]
#[must_use]
pub fn generate_views_std_names() -> String {
    match CodeGenerator::new().generate_views(&std_names_dictionary()) {
        Ok(code) => code,
        Err(err) => panic!("the standard-names views must generate: {err}"),
    }
}
