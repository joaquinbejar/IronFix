/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Compiles the code generated from a dictionary whose fields and messages
//! are named after standard library items (`std_names_common`), and reads
//! and writes a message through it.
//!
//! The generated code names every standard item it uses by its absolute
//! path (`::std::vec::Vec`, `::core::option::Option`, ...), so a generated
//! enumeration or struct named `Vec`, `String`, `Option` or `Result` cannot
//! capture it. Regenerate the golden files after an intentional change with:
//!
//! ```text
//! cargo test -p ironfix-codegen --test regenerate_golden -- --ignored
//! ```
//!
//! The `#[allow(dead_code)]` on the modules below belongs to this test
//! binary, where the generated `pub` items are not exported.

mod std_names_common;

#[allow(dead_code)]
mod generated {
    include!("golden/std_names.rs");
}

#[allow(dead_code)]
mod std_views {
    include!("golden/views_std_names.rs");
}

use ironfix_tagvalue::{Decoder, Encoder};
use std::fmt::Debug;

/// The tag=value encoder as the sink of the generated writers.
impl std_views::writers::Sink for Encoder {
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

#[test]
fn test_std_names_match_the_compiled_golden_files() {
    let regenerate =
        "regenerate with: cargo test -p ironfix-codegen --test regenerate_golden -- --ignored";
    assert!(
        std_names_common::generate_std_names() == include_str!("golden/std_names.rs"),
        "generated code drifted from golden/std_names.rs; {regenerate}"
    );
    assert!(
        std_names_common::generate_views_std_names() == include_str!("golden/views_std_names.rs"),
        "generated views drifted from golden/views_std_names.rs; {regenerate}"
    );
}

#[test]
fn test_default_output_structs_named_after_std_items_compile() {
    // A struct named `Option` sits next to fields typed
    // `::core::option::Option<::std::string::String>`.
    let message = generated::messages::Option {
        vec: 'A',
        string: Some("X".to_owned()),
        option: None,
        result: None,
        flags: None,
        text: Some("text".to_owned()),
        raw_data_length: None,
        raw_data: Some(vec![1, 2, 3]),
        no_items: Some(vec![generated::messages::OptionNoItemsEntry {
            item_name: "item".to_owned(),
        }]),
    };
    assert_eq!(message.raw_data.as_deref(), Some(&[1u8, 2, 3][..]));
    assert_eq!(generated::fields::VEC, 5001);
}

#[test]
fn test_enumerations_named_after_std_items_read_and_write() {
    use std_views::enums;
    use std_views::writers::{OptionFields, OptionNoItemsFields};

    let items = [OptionNoItemsFields {
        item_name: Some("item"),
    }];
    let fields = OptionFields {
        vec: Some(enums::Vec::Bravo),
        string: Some(enums::String::XRay),
        option: Some(enums::Option::One),
        result: Some(enums::Result::Yes),
        flags: &[enums::Flags::Alpha, enums::Flags::Bravo],
        text: Some("text"),
        raw_data: Some(&b"\x01data"[..]),
        no_items: &items,
    };
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, "U1");
    encoder.put_str(49, "S");
    encoder.put_str(56, "T");
    encoder.put_uint(34, 1);
    encoder.put_str(52, "20260712-10:00:00");
    ok(fields.write(&mut encoder), "the body writes");
    let frame = ok(encoder.finish(), "the frame encodes").to_vec();

    let mut decoder = Decoder::new(&frame);
    let msg = ok(decoder.decode(), "the frame decodes");
    let Some(view) = std_views::views::OptionView::from_message(&msg) else {
        panic!("an Option view");
    };
    assert_eq!(ok(view.vec(), "Vec"), enums::Vec::Bravo);
    assert_eq!(view.string(), Some(enums::String::XRay));
    assert_eq!(view.option(), Some(enums::Option::One));
    assert_eq!(view.result(), Some(enums::Result::Yes));
    let flags: Vec<enums::Flags<'_>> = match ok(view.flags(), "Flags") {
        Some(tokens) => tokens.collect(),
        None => panic!("the flags are present"),
    };
    assert_eq!(flags, [enums::Flags::Alpha, enums::Flags::Bravo]);
    assert_eq!(view.raw_data(), Some(&b"\x01data"[..]));
}
