/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! A dictionary whose member names collide with each other only once a Rust
//! keyword is escaped, for the golden files `golden/keyword_names.rs`
//! (`CodeGenerator::generate`) and `golden/views_keyword_names.rs`
//! (`CodeGenerator::generate_views`).
//!
//! `crate` and `self` have no raw form, so the generator escapes them with a
//! trailing underscore: a field or component `Crate` becomes `crate_`, which
//! is also the plain snake case of `Crate_`, and `Self` becomes `self_`, the
//! plain snake case of `Self_`. Every pair is listed in both orders, as two
//! fields, a field and a component, two components, and a field and a group,
//! so an allocator that checks uniqueness before escaping emits the same
//! identifier twice in at least one of them.
//!
//! A message and a component are also named `Self`, each declaring a group:
//! a type named `Self` must be escaped, and a name built from it must not
//! keep the escape (`Self_NoLinesEntry`, `Self_View` or `Self_2` fail
//! `non_camel_case_types`).

use ironfix_codegen::CodeGenerator;
use ironfix_dictionary::schema::{
    ComponentDef, ComponentRef, Dictionary, FieldDef, FieldRef as SchemaFieldRef, FieldType,
    GroupDef, Member, MessageCategory, MessageDef, Version,
};

/// A field reference member.
fn field(tag: u32, name: &str, required: bool) -> Member {
    Member::Field(SchemaFieldRef {
        tag,
        name: name.to_string(),
        required,
    })
}

/// A component reference member.
fn component(name: &str, required: bool) -> Member {
    Member::Component(ComponentRef::new(name, required))
}

/// The `Self` group: a count field and one entry field.
fn self_group() -> Member {
    Member::Group(GroupDef::new(
        6006,
        "Self",
        6005,
        false,
        vec![field(6005, "Note", true)],
    ))
}

/// A group of `Line` entries.
fn line_group(count_tag: u32, name: &str) -> Member {
    Member::Group(GroupDef::new(
        count_tag,
        name,
        6009,
        false,
        vec![field(6009, "Line", true)],
    ))
}

/// The dictionary: the fields `Crate_`, `Crate`, `Self_` and `Note`, a
/// group named `Self`, three components (`Crate`, `Self`, `Self_`) holding
/// `Note` (`Self` also a `NoLines` group), one message per pair and order,
/// and a message named `Self` with a component `Self` and a `NoNotes`
/// group.
#[must_use]
pub fn keyword_names_dictionary() -> Dictionary {
    let mut dict = Dictionary::new(Version::Fix44);
    for (tag, name, field_type) in [
        (6001u32, "Crate_", FieldType::String),
        (6002, "Crate", FieldType::String),
        (6003, "Self_", FieldType::String),
        (6005, "Note", FieldType::String),
        (6006, "NoSelf", FieldType::NumInGroup),
        (6007, "NoNotes", FieldType::NumInGroup),
        (6008, "NoLines", FieldType::NumInGroup),
        (6009, "Line", FieldType::String),
    ] {
        dict.add_field(FieldDef::new(tag, name, field_type));
    }
    for name in ["Crate", "Self_"] {
        dict.add_component(ComponentDef::new(name, vec![field(6005, "Note", false)]));
    }
    dict.add_component(ComponentDef::new(
        "Self",
        vec![field(6005, "Note", false), line_group(6008, "NoLines")],
    ));
    let messages: [(&str, &str, Vec<Member>); 9] = [
        (
            "U1",
            "FieldThenComponent",
            vec![field(6001, "Crate_", false), component("Crate", false)],
        ),
        (
            "U2",
            "ComponentThenField",
            vec![component("Crate", true), field(6001, "Crate_", true)],
        ),
        (
            "U3",
            "UnderscoredThenPlainField",
            vec![field(6001, "Crate_", false), field(6002, "Crate", false)],
        ),
        (
            "U4",
            "PlainThenUnderscoredField",
            vec![field(6002, "Crate", false), field(6001, "Crate_", false)],
        ),
        (
            "U5",
            "SelfThenUnderscoredComponent",
            vec![component("Self", false), component("Self_", false)],
        ),
        (
            "U6",
            "UnderscoredThenSelfComponent",
            vec![component("Self_", false), component("Self", false)],
        ),
        (
            "U7",
            "GroupThenUnderscoredField",
            vec![self_group(), field(6003, "Self_", false)],
        ),
        (
            "U8",
            "UnderscoredFieldThenGroup",
            vec![field(6003, "Self_", false), self_group()],
        ),
        (
            "U9",
            "Self",
            vec![component("Self", false), line_group(6007, "NoNotes")],
        ),
    ];
    for (msg_type, name, members) in messages {
        dict.add_message(MessageDef::new(
            msg_type,
            name,
            MessageCategory::App,
            members,
        ));
    }
    dict
}

/// Generates the default output of [`keyword_names_dictionary`]
/// (`golden/keyword_names.rs`).
#[track_caller]
#[must_use]
pub fn generate_keyword_names() -> String {
    match CodeGenerator::new().generate(&keyword_names_dictionary()) {
        Ok(code) => code,
        Err(err) => panic!("the keyword-names dictionary must generate: {err}"),
    }
}

/// Generates the views of [`keyword_names_dictionary`]
/// (`golden/views_keyword_names.rs`).
#[track_caller]
#[must_use]
pub fn generate_views_keyword_names() -> String {
    match CodeGenerator::new().generate_views(&keyword_names_dictionary()) {
        Ok(code) => code,
        Err(err) => panic!("the keyword-names views must generate: {err}"),
    }
}
