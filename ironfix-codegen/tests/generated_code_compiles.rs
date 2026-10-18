/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! Hands the generator's own output to the compiler.
//!
//! Three golden files are compiled here, each the generator's output for one
//! dictionary:
//!
//! - `golden/sample.rs`: the fixture dictionary in `common`;
//! - `golden/fix42.rs`: the embedded QuickFIX FIX 4.2 dictionary in full;
//! - `golden/fixt11.rs`: the embedded QuickFIX FIXT 1.1 dictionary in full.
//!
//! The `include!`s below compile that text, and the `matches_the_compiled_golden_file`
//! tests assert the generator still produces it, so a change that makes the
//! generator emit invalid Rust fails the build rather than shipping.
//!
//! Regenerate after an intentional change with:
//!
//! ```text
//! cargo test -p ironfix-codegen --test regenerate_golden -- --ignored
//! ```
//!
//! Generated files resolve `rust_decimal::Decimal` against the real
//! `rust_decimal`, a dev-dependency of `ironfix-codegen`.
//!
//! Not compiled here: the full FIX 4.4 output (about 1.4 MB) and the full
//! FIX 5.0 SP2 output (about 50 MB). The generator's own unit tests check that
//! both generate. The views output (`CodeGenerator::generate_views`) is
//! compiled in `generated_views.rs`.

#![allow(dead_code)]

mod common;

mod generated {
    include!("golden/sample.rs");
}

// FIX 4.2 names its indication-of-interest message `IOI`, which the generator
// emits verbatim as the struct name; that is the dictionary's name, not a
// defect of the compiled output.
#[allow(clippy::upper_case_acronyms)]
mod generated_fix42 {
    include!("golden/fix42.rs");
}

mod generated_fixt11 {
    // FIXT 1.1 defines no price, quantity, or amount field, so the generated
    // file declares no decimal alias and needs no stand-in.
    include!("golden/fixt11.rs");
}

#[test]
fn test_generate_fix42_dictionary_matches_the_compiled_golden_file() {
    let golden = include_str!("golden/fix42.rs");
    assert!(
        common::generate_fix42() == golden,
        "generated FIX 4.2 output drifted from golden/fix42.rs, which this test compiles; \
         regenerate with: cargo test -p ironfix-codegen --test regenerate_golden -- --ignored"
    );
}

#[test]
fn test_generate_fixt11_dictionary_matches_the_compiled_golden_file() {
    let golden = include_str!("golden/fixt11.rs");
    assert!(
        common::generate_fixt11() == golden,
        "generated FIXT 1.1 output drifted from golden/fixt11.rs, which this test compiles; \
         regenerate with: cargo test -p ironfix-codegen --test regenerate_golden -- --ignored"
    );
}

#[test]
fn test_generated_fix42_carries_its_tags_and_types() {
    use generated_fix42::fields;
    use generated_fix42::messages::Heartbeat;

    assert_eq!(fields::HANDL_INST, 21);
    assert_eq!(fields::MDENTRY_DATE, 272);
    // A FIX 4.2 price is the decimal alias, never binary floating point.
    let price: generated_fix42::FixDecimal = rust_decimal::Decimal::new(12345, 2);
    assert_eq!(price.to_string(), "123.45");
    let heartbeat = Heartbeat {
        test_req_id: Some("PING".to_string()),
    };
    assert_eq!(heartbeat.test_req_id.as_deref(), Some("PING"));
    assert!(!include_str!("golden/fix42.rs").contains("f64"));
}

#[test]
fn test_generated_fixt11_carries_its_tags_and_types() {
    use generated_fixt11::fields;
    use generated_fixt11::messages::{Heartbeat, XMLnonFIX};

    assert_eq!(fields::APPL_VER_ID, 1128);
    assert_eq!(fields::DEFAULT_APPL_VER_ID, 1137);
    let heartbeat = Heartbeat { test_req_id: None };
    assert!(heartbeat.test_req_id.is_none());
    // The self-closing XMLnonFIX definition becomes a field-less struct.
    let _ = XMLnonFIX {};
}

#[test]
fn test_generate_sample_dictionary_matches_the_compiled_golden_file() {
    let golden = include_str!("golden/sample.rs");
    assert_eq!(
        common::generate_sample(),
        golden,
        "generated output drifted from golden/sample.rs, which this test compiles; \
         regenerate with: cargo test -p ironfix-codegen --test regenerate_golden -- --ignored"
    );
}

#[test]
fn test_golden_file_declares_the_shapes_it_is_meant_to_cover() {
    let golden = include_str!("golden/sample.rs");
    // A Rust keyword survives as a raw identifier.
    assert!(golden.contains("pub r#yield: ::core::option::Option<FixDecimal>,"));
    // A required field is bare, an optional one is wrapped.
    assert!(golden.contains("pub cl_ord_id: ::std::string::String,"));
    assert!(golden.contains("pub price: ::core::option::Option<FixDecimal>,"));
    // Two field names collapsing onto one identifier are disambiguated by tag.
    assert!(golden.contains("pub cl_ord_id_12: ::core::option::Option<::std::string::String>,"));
    // The component contributes Symbol, as an optional field.
    assert!(golden.contains("pub symbol: ::core::option::Option<::std::string::String>,"));
    // A repeating group becomes a Vec of a generated entry struct.
    assert!(golden.contains(
        "pub no_party_ids: ::core::option::Option<::std::vec::Vec<NewOrderSingleNoPartyIDsEntry>>,"
    ));
    assert!(golden.contains("pub struct NewOrderSingleNoPartyIDsEntry {"));
    // And a group nested inside that group gets its own entry struct.
    assert!(golden.contains("pub struct NewOrderSingleNoPartyIDsEntryNoPartySubIDsEntry {"));
    // No monetary value is ever binary floating point.
    assert!(!golden.contains("f64"));
}

#[test]
fn test_generated_types_are_constructible() {
    use generated::messages::{
        Heartbeat, NewOrderSingle, NewOrderSingleNoPartyIDsEntry,
        NewOrderSingleNoPartyIDsEntryNoPartySubIDsEntry,
    };

    let entry = NewOrderSingleNoPartyIDsEntry {
        party_id: "PARTY".to_string(),
        no_party_sub_ids: Some(vec![NewOrderSingleNoPartyIDsEntryNoPartySubIDsEntry {
            party_sub_id: "SUB".to_string(),
        }]),
    };
    let order = NewOrderSingle {
        cl_ord_id: "ORDER1".to_string(),
        cl_ord_id_12: None,
        msg_seq_num: Some(1),
        poss_dup_flag: Some(false),
        price: Some(rust_decimal::Decimal::new(12345, 2)),
        side: '1',
        raw_data: Some(vec![0x41]),
        r#yield: None,
        symbol: Some("AAPL".to_string()),
        no_party_ids: Some(vec![entry]),
    };

    assert_eq!(order.cl_ord_id, "ORDER1");
    assert_eq!(order.symbol.as_deref(), Some("AAPL"));
    assert_eq!(order.no_party_ids.map(|group| group.len()), Some(1));
    let _ = Heartbeat {};
}

#[test]
fn test_generated_field_constants_carry_their_tags() {
    assert_eq!(generated::fields::CL_ORD_ID, 11);
    assert_eq!(generated::fields::CL_ORD_ID_12, 12);
    assert_eq!(generated::fields::YIELD, 236);
}
