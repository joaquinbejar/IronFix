/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! # IronFix codegen check
//!
//! Compiles, in full, as a library under the workspace lints, what
//! `ironfix_codegen::CodeGenerator` emits for the embedded dictionaries:
//!
//! - the views, enumerations and writers (`generate_views`) of FIX 4.4,
//!   FIX 4.2 and FIXT 1.1, in the modules `fix44`, `fix42` and `fixt11`;
//! - the data definitions (`generate`, the default output) of FIX 4.4,
//!   FIX 4.2, FIXT 1.1 and FIX 5.0 SP2, in the module `data`.
//!
//! `make lint` (`clippy --all-targets -D warnings`) and `make doc`
//! (`-D missing_docs`) check the generated text, which carries no
//! `#[allow]`, and so does this crate. The FIX 5.0 SP2 views (about 31 MB of
//! source) are not compiled here.
//!
//! It also compiles both outputs, `CodeGenerator::generate` and
//! `CodeGenerator::generate_views`, for the dictionary that
//! `Dictionary::from_orchestra_xml` loads from the FIX Trading Community's
//! FIX 4.4 Orchestra repository `ironfix-dictionary` embeds, loaded directly.
//!
//! `build.rs` generates the sources into `OUT_DIR`; Cargo reruns it when
//! `build.rs`, the Orchestra fixture, or one of its build dependencies
//! (`ironfix-codegen`, `ironfix-dictionary`, the embedded XML they include)
//! changes, so there is no golden file to keep in step. Not published: it is
//! a check, left out of `make publish-all`, the semver matrix and the
//! coverage report.
#![deny(missing_docs)]

/// The full views of the embedded FIX 4.4 dictionary.
pub mod fix44 {
    include!(concat!(env!("OUT_DIR"), "/fix44_views.rs"));
}

/// The full views of the embedded FIX 4.2 dictionary.
pub mod fix42 {
    include!(concat!(env!("OUT_DIR"), "/fix42_views.rs"));
}

/// The full views of the embedded FIXT 1.1 dictionary.
pub mod fixt11 {
    include!(concat!(env!("OUT_DIR"), "/fixt11_views.rs"));
}

/// The default output for the FIX 4.4 Orchestra repository.
pub mod orchestra_fix44 {
    include!(concat!(env!("OUT_DIR"), "/orchestra_fix44.rs"));
}

/// The full views of the FIX 4.4 Orchestra repository.
pub mod orchestra_fix44_views {
    include!(concat!(env!("OUT_DIR"), "/orchestra_fix44_views.rs"));
}

/// The full data definitions (`CodeGenerator::generate`) of the embedded
/// dictionaries: tag constants, message structs, one struct per component
/// and one per repeating-group definition.
pub mod data {
    /// The data definitions of the embedded FIX 4.4 dictionary.
    pub mod fix44 {
        include!(concat!(env!("OUT_DIR"), "/fix44_data.rs"));
    }

    /// The data definitions of the embedded FIX 4.2 dictionary.
    pub mod fix42 {
        include!(concat!(env!("OUT_DIR"), "/fix42_data.rs"));
    }

    /// The data definitions of the embedded FIXT 1.1 dictionary.
    pub mod fixt11 {
        include!(concat!(env!("OUT_DIR"), "/fixt11_data.rs"));
    }

    /// The data definitions of the embedded FIX 5.0 SP2 dictionary.
    pub mod fix50sp2 {
        include!(concat!(env!("OUT_DIR"), "/fix50sp2_data.rs"));
    }
}

#[cfg(test)]
mod tests {
    use super::{data, fix44};
    use ironfix_core::message::RawMessage;
    use ironfix_tagvalue::Decoder;
    use rust_decimal::Decimal;
    use std::fmt::Debug;

    /// Unwraps a `Result` with test context instead of `.unwrap()`.
    #[track_caller]
    fn ok<T, E: Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{what}: {err:?}"),
        }
    }

    /// Decodes a frame, without checking its checksum.
    fn decode<'a>(text: &'a str) -> RawMessage<'a> {
        let mut decoder = Decoder::new(text.as_bytes()).with_checksum_validation(false);
        ok(decoder.decode(), "the frame decodes")
    }

    #[test]
    fn test_full_fix44_views_read_an_execution_report() {
        // ExecutionReport is not among the in-repo golden messages: this
        // reads it through the full generated FIX 4.4 views.
        let body = "35=8\x0149=S\x0156=T\x0134=1\x0152=20260712-10:00:00\x01\
                    37=ORDER-1\x0117=EXEC-1\x01150=F\x0139=2\x0155=EURUSD\x0154=1\x01\
                    151=0\x0114=100\x016=1.2345\x01";
        let text = format!("8=FIX.4.4\x019={}\x01{body}10=000\x01", body.len());
        let msg = decode(&text);
        let Some(report) = fix44::views::ExecutionReportView::from_message(&msg) else {
            panic!("an ExecutionReport view");
        };
        assert_eq!(ok(report.order_id(), "OrderID"), "ORDER-1");
        assert_eq!(
            ok(report.exec_type(), "ExecType"),
            fix44::enums::ExecType::Trade
        );
        assert_eq!(
            ok(report.ord_status(), "OrdStatus"),
            fix44::enums::OrdStatus::Filled
        );
        assert_eq!(ok(report.cum_qty(), "CumQty"), Decimal::new(100, 0));
        assert_eq!(ok(report.avg_px(), "AvgPx"), Decimal::new(12345, 4));
        assert_eq!(ok(report.symbol(), "Symbol"), Some("EURUSD"));
    }

    /// The FIX 4.4 Orchestra repository build.rs generated from.
    const ORCHESTRA_FIX44: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ironfix-dictionary/spec/orchestra/OrchestraFIX44.xml"
    ));

    /// Generation is deterministic: run again at test time, both generators
    /// produce, byte for byte, the text build.rs wrote and this crate
    /// compiled.
    #[test]
    fn test_orchestra_fix44_generation_is_deterministic() {
        let import = ok(
            ironfix_dictionary::Dictionary::from_orchestra_xml(ORCHESTRA_FIX44),
            "the FIX 4.4 Orchestra repository loads",
        );
        let generator = ironfix_codegen::CodeGenerator::new();
        let code = ok(generator.generate(import.dictionary()), "generate");
        let views = ok(
            generator.generate_views(import.dictionary()),
            "generate_views",
        );
        // What this crate compiled, as `orchestra_fix44` and
        // `orchestra_fix44_views`.
        assert!(code == include_str!(concat!(env!("OUT_DIR"), "/orchestra_fix44.rs")));
        assert!(views == include_str!(concat!(env!("OUT_DIR"), "/orchestra_fix44_views.rs")));
    }

    #[test]
    fn test_orchestra_fix44_default_output_types_prices_as_decimals() {
        use super::orchestra_fix44::{fields, messages};
        assert_eq!(fields::CL_ORD_ID, 11);
        assert_eq!(fields::AVG_PX, 6);
        // Compiles only if AvgPx(6) and Price(44) are rust_decimal::Decimal.
        let avg_px = |report: &messages::ExecutionReport| -> Decimal { report.avg_px };
        let price = |report: &messages::ExecutionReport| -> Option<Decimal> { report.price };
        let _ = (avg_px, price);
    }

    #[test]
    fn test_orchestra_fix44_views_read_like_the_quickfix_views() {
        use super::orchestra_fix44_views as orchestra;
        let body = "35=8\x0149=S\x0156=T\x0134=1\x0152=20260712-10:00:00\x01\
                    37=ORDER-1\x0117=EXEC-1\x01150=F\x0139=2\x0155=EURUSD\x0154=1\x01\
                    453=1\x01448=TRADER\x01447=D\x01452=11\x01\
                    151=0\x0114=100\x016=1.2345\x01";
        let text = format!("8=FIX.4.4\x019={}\x01{body}10=000\x01", body.len());
        let msg = decode(&text);
        let Some(from_orchestra) = orchestra::views::ExecutionReportView::from_message(&msg) else {
            panic!("an Orchestra ExecutionReport view");
        };
        let Some(from_quickfix) = fix44::views::ExecutionReportView::from_message(&msg) else {
            panic!("an embedded FIX 4.4 ExecutionReport view");
        };
        assert_eq!(
            ok(from_orchestra.order_id(), "OrderID"),
            ok(from_quickfix.order_id(), "OrderID")
        );
        assert_eq!(
            ok(from_orchestra.exec_type(), "ExecType"),
            orchestra::enums::ExecType::Trade
        );
        assert_eq!(
            ok(from_orchestra.avg_px(), "AvgPx"),
            ok(from_quickfix.avg_px(), "AvgPx")
        );
        assert_eq!(
            ok(from_orchestra.symbol(), "Symbol"),
            ok(from_quickfix.symbol(), "Symbol")
        );
        // The Parties group, named after its count field in both.
        let Some(parties) = ok(from_orchestra.no_party_ids(), "NoPartyIDs") else {
            panic!("the Parties group is present");
        };
        let ids: Vec<&str> = parties
            .map(|party| ok(party.party_id(), "PartyID"))
            .collect();
        assert_eq!(ids, ["TRADER"]);
    }

    #[test]
    fn test_full_fix50sp2_data_shares_one_type_per_component() {
        use data::fix50sp2::components::Instrument;
        use data::fix50sp2::messages::{
            ExecutionReport, NewOrderSingle, NewOrderSingleNoPartyIDsEntry,
            NewOrderSingleNoPartyIDsNoPartySubIDsEntry,
        };

        // NewOrderSingle and ExecutionReport hold the same component type,
        // so one function reads the instrument of either. A required
        // component is a bare field: the symbol is one access away.
        let symbol = |instrument: &Instrument| instrument.symbol.clone();
        let of_order: fn(&NewOrderSingle) -> &Instrument = |order| &order.instrument;
        let of_report: fn(&ExecutionReport) -> &Instrument = |report| &report.instrument;

        // The FIX Orchestra repository holds Parties as a repeating group,
        // not a component, so each message has its own entry type; the
        // NoPartySubIDs group nests inside it.
        let party = NewOrderSingleNoPartyIDsEntry {
            party_id: Some("BROKER-1".to_owned()),
            party_idsource: Some('D'),
            party_role: Some(1),
            party_role_qualifier: None,
            no_party_sub_ids: Some(vec![NewOrderSingleNoPartyIDsNoPartySubIDsEntry {
                party_sub_id: Some("DESK-7".to_owned()),
                party_sub_idtype: Some(4),
            }]),
        };
        assert_eq!(party.party_id.as_deref(), Some("BROKER-1"));
        let parties: fn(&NewOrderSingle) -> usize =
            |order| order.no_party_ids.as_ref().map_or(0, Vec::len);
        // CumQty (14) is a required FIX Qty: a decimal, never binary floating
        // point.
        let cum_qty: fn(&ExecutionReport) -> Decimal = |report| report.cum_qty;
        let _ = (symbol, of_order, of_report, parties, cum_qty);
    }
}
