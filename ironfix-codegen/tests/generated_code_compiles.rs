/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! Hands the generator's own output to the compiler.
//!
//! `golden/sample.rs` is the fixture dictionary in `common` run through the
//! generator.
//! The `include!` below compiles that text, and
//! `test_generate_sample_dictionary_matches_the_compiled_golden_file` asserts
//! the generator still produces it — so a change that makes the generator emit
//! invalid Rust fails the build rather than shipping.
//!
//! Regenerate after an intentional change with:
//!
//! ```text
//! cargo test -p ironfix-codegen --test regenerate_golden -- --ignored
//! ```
//!
//! The **full** FIX 4.4 output is not compiled here: it resolves
//! `rust_decimal::Decimal`, and `rust_decimal` is not a dependency of
//! `ironfix-codegen`. The `rust_decimal` module below stands in for it so the
//! rest of the generated file is still type-checked.

#![allow(dead_code)]

mod common;

mod generated {
    include!("golden/sample.rs");

    /// Stands in for the `rust_decimal` crate, which is not a dependency of
    /// `ironfix-codegen`.
    ///
    /// The generated alias resolves against this module, so everything else in
    /// the generated file is compiled for real. That the alias points at
    /// `rust_decimal::Decimal` in a consumer's crate is asserted textually in
    /// the generator's own tests.
    pub mod rust_decimal {
        /// Stand-in for `rust_decimal::Decimal`.
        pub type Decimal = i64;
    }
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
    assert!(golden.contains("pub r#yield: Option<FixDecimal>,"));
    // A required field is bare, an optional one is wrapped.
    assert!(golden.contains("pub cl_ord_id: String,"));
    assert!(golden.contains("pub price: Option<FixDecimal>,"));
    // Two field names collapsing onto one identifier are disambiguated by tag.
    assert!(golden.contains("pub cl_ord_id_12: Option<String>,"));
    // The component contributes Symbol, as an optional field.
    assert!(golden.contains("pub symbol: Option<String>,"));
    // A repeating group becomes a Vec of a generated entry struct.
    assert!(golden.contains("pub no_party_ids: Option<Vec<NewOrderSingleNoPartyIDsEntry>>,"));
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
        price: Some(12345),
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
