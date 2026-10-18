/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Compiles the code generated from a dictionary whose member names collide
//! only once a keyword is escaped (`keyword_names_common`): `Crate` and
//! `Crate_` both spell `crate_`, `Self` and `Self_` both spell `self_`. Each
//! pair is listed in both orders, as two fields, a field and a component, two
//! components, and a field and a group; every struct field and every view
//! accessor must get its own identifier, or these modules do not compile. A
//! message and a component named `Self` check that a type name built from
//! an escaped one keeps no underscore (`SelfNoLinesEntry`, `SelfView`).
//! Regenerate the golden files after an intentional change with:
//!
//! ```text
//! cargo test -p ironfix-codegen --test regenerate_golden -- --ignored
//! ```
//!
//! The `#[allow(dead_code)]` on the modules below belongs to this test
//! binary, where the generated `pub` items are not exported; the generated
//! text itself carries no `#[allow]`. `non_snake_case` and
//! `non_camel_case_types` are denied so that a disambiguated identifier
//! holding `__`, or a type name such as `Self_2`, would fail here too.

mod keyword_names_common;

#[allow(dead_code)]
#[deny(non_snake_case, non_camel_case_types)]
mod generated {
    include!("golden/keyword_names.rs");
}

#[allow(dead_code)]
#[deny(non_snake_case, non_camel_case_types)]
mod keyword_views {
    include!("golden/views_keyword_names.rs");
}

use ironfix_tagvalue::{Decoder, Encoder};
use std::fmt::Debug;

/// The tag=value encoder as the sink of the generated writers.
impl keyword_views::writers::Sink for Encoder {
    fn field(&mut self, tag: u32, value: &[u8]) {
        self.put_raw(tag, value);
    }

    fn data(&mut self, length_tag: u32, data_tag: u32, value: &[u8]) {
        self.put_data(length_tag, data_tag, value);
    }
}

/// Unwraps a `Result` with test context instead of `.unwrap()`.
#[track_caller]
fn ok<T, E: Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what}: {err:?}"),
    }
}

/// Encodes a frame of type `msg_type` whose body `write` fills.
fn frame(msg_type: &str, write: impl FnOnce(&mut Encoder)) -> Vec<u8> {
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, msg_type);
    encoder.put_str(49, "S");
    encoder.put_str(56, "T");
    encoder.put_uint(34, 1);
    encoder.put_str(52, "20260712-10:00:00");
    write(&mut encoder);
    ok(encoder.finish(), "the frame encodes").to_vec()
}

#[test]
fn test_keyword_names_match_the_compiled_golden_files() {
    let regenerate =
        "regenerate with: cargo test -p ironfix-codegen --test regenerate_golden -- --ignored";
    assert!(
        keyword_names_common::generate_keyword_names() == include_str!("golden/keyword_names.rs"),
        "generated code drifted from golden/keyword_names.rs; {regenerate}"
    );
    assert!(
        keyword_names_common::generate_views_keyword_names()
            == include_str!("golden/views_keyword_names.rs"),
        "generated views drifted from golden/views_keyword_names.rs; {regenerate}"
    );
    for golden in [
        include_str!("golden/keyword_names.rs"),
        include_str!("golden/views_keyword_names.rs"),
    ] {
        assert!(!golden.contains("#[allow"));
    }
}

#[test]
fn test_crate_field_and_component_get_distinct_fields_in_both_orders() {
    use generated::components::Crate;
    use generated::messages::{ComponentThenField, FieldThenComponent};

    let note = Crate {
        note: Some("note".to_owned()),
    };
    // The member listed first takes `crate_`; the other is qualified.
    let field_first = FieldThenComponent {
        crate_: Some("field".to_owned()),
        crate_component: Some(note.clone()),
    };
    let component_first = ComponentThenField {
        crate_: note,
        crate_6001: "field".to_owned(),
    };
    assert_eq!(field_first.crate_.as_deref(), Some("field"));
    assert_eq!(
        field_first
            .crate_component
            .and_then(|component| component.note),
        Some("note".to_owned())
    );
    assert_eq!(component_first.crate_6001, "field");
    assert_eq!(component_first.crate_.note.as_deref(), Some("note"));
}

#[test]
fn test_crate_fields_get_distinct_fields_in_both_orders() {
    use generated::messages::{PlainThenUnderscoredField, UnderscoredThenPlainField};

    // Crate_ is tag 6001, Crate tag 6002: the second listed takes its tag.
    let underscored_first = UnderscoredThenPlainField {
        crate_: Some("6001".to_owned()),
        crate_6002: Some("6002".to_owned()),
    };
    let plain_first = PlainThenUnderscoredField {
        crate_: Some("6002".to_owned()),
        crate_6001: Some("6001".to_owned()),
    };
    assert_ne!(underscored_first.crate_, underscored_first.crate_6002);
    assert_ne!(plain_first.crate_, plain_first.crate_6001);
}

#[test]
fn test_self_components_get_distinct_fields_in_both_orders() {
    use generated::components::{Self_, Self2};
    use generated::messages::{SelfThenUnderscoredComponent, UnderscoredThenSelfComponent};

    // The component `Self` is the type `Self_` (a keyword cannot name a
    // type), so the component `Self_` is the type `Self2`.
    let self_first = SelfThenUnderscoredComponent {
        self_: Some(Self_ {
            note: None,
            no_lines: None,
        }),
        self_component: Some(Self2 {
            note: Some("underscored".to_owned()),
        }),
    };
    let underscored_first = UnderscoredThenSelfComponent {
        self_: Some(Self2 { note: None }),
        self_component: Some(Self_ {
            note: Some("self".to_owned()),
            no_lines: None,
        }),
    };
    assert_eq!(
        self_first
            .self_component
            .and_then(|component| component.note),
        Some("underscored".to_owned())
    );
    assert_eq!(
        underscored_first
            .self_component
            .and_then(|component| component.note),
        Some("self".to_owned())
    );
}

#[test]
fn test_self_group_and_field_get_distinct_fields_in_both_orders() {
    use generated::messages::{
        GroupThenUnderscoredField, GroupThenUnderscoredFieldSelfEntry, UnderscoredFieldThenGroup,
        UnderscoredFieldThenGroupSelfEntry,
    };

    // The group `Self` counts with tag 6006, the field `Self_` is tag 6003.
    let group_first = GroupThenUnderscoredField {
        self_: Some(vec![GroupThenUnderscoredFieldSelfEntry {
            note: "entry".to_owned(),
        }]),
        self_6003: Some("field".to_owned()),
    };
    let field_first = UnderscoredFieldThenGroup {
        self_: Some("field".to_owned()),
        self_6006: Some(vec![UnderscoredFieldThenGroupSelfEntry {
            note: "entry".to_owned(),
        }]),
    };
    assert_eq!(group_first.self_.map(|entries| entries.len()), Some(1));
    assert_eq!(field_first.self_6006.map(|entries| entries.len()), Some(1));
}

#[test]
fn test_views_and_writers_keep_the_two_crate_fields_apart() {
    use keyword_views::views::{PlainThenUnderscoredFieldView, UnderscoredThenPlainFieldView};
    use keyword_views::writers::{
        PlainThenUnderscoredFieldFields, UnderscoredThenPlainFieldFields,
    };

    // Each accessor reads its own tag, in both member orders.
    let fields = UnderscoredThenPlainFieldFields {
        crate_: Some("underscored"),
        crate_6002: Some("plain"),
    };
    let bytes = frame("U3", |encoder| ok(fields.write(encoder), "the body writes"));
    let mut decoder = Decoder::new(&bytes);
    let msg = ok(decoder.decode(), "the frame decodes");
    assert_eq!(msg.get_field_str(6001), Some("underscored"));
    assert_eq!(msg.get_field_str(6002), Some("plain"));
    let Some(view) = UnderscoredThenPlainFieldView::from_message(&msg) else {
        panic!("an UnderscoredThenPlainField view");
    };
    assert_eq!(ok(view.crate_(), "Crate_"), Some("underscored"));
    assert_eq!(ok(view.crate_6002(), "Crate"), Some("plain"));

    let fields = PlainThenUnderscoredFieldFields {
        crate_: Some("plain"),
        crate_6001: Some("underscored"),
    };
    let bytes = frame("U4", |encoder| ok(fields.write(encoder), "the body writes"));
    let mut decoder = Decoder::new(&bytes);
    let msg = ok(decoder.decode(), "the frame decodes");
    let Some(view) = PlainThenUnderscoredFieldView::from_message(&msg) else {
        panic!("a PlainThenUnderscoredField view");
    };
    assert_eq!(ok(view.crate_(), "Crate"), Some("plain"));
    assert_eq!(ok(view.crate_6001(), "Crate_"), Some("underscored"));
}

#[test]
fn test_types_named_self_compose_without_the_escape() {
    use generated::components::{Self_ as SelfComponent, SelfNoLinesEntry};
    use generated::messages::{Self_ as SelfMessage, SelfNoNotesEntry};

    // The bare types are escaped; the names built from them are not.
    let message = SelfMessage {
        self_: Some(SelfComponent {
            note: None,
            no_lines: Some(vec![SelfNoLinesEntry {
                line: "component line".to_owned(),
            }]),
        }),
        no_notes: Some(vec![SelfNoNotesEntry {
            line: "message line".to_owned(),
        }]),
    };
    assert_eq!(message.no_notes.map(|entries| entries.len()), Some(1));

    // The views name the same groups alike, without the escape either.
    let views = include_str!("golden/views_keyword_names.rs");
    for view in [
        "pub struct SelfView<'m, 'a> {",
        "pub struct SelfNoLinesView<'m, 'a> {",
        "pub struct SelfNoNotesView<'m, 'a> {",
    ] {
        assert!(views.contains(view), "{view}");
    }
}
