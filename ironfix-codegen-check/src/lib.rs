/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! # IronFix codegen check
//!
//! Compiles the views, enumerations and writers that
//! `ironfix_codegen::CodeGenerator::generate_views` emits for the embedded
//! FIX 4.4, FIX 4.2 and FIXT 1.1 dictionaries, in full, as a library under
//! the workspace lints: `make lint` (`clippy --all-targets -D warnings`) and
//! `make doc` (`-D missing_docs`) check the generated text, which carries no
//! `#[allow]`, and so does this crate.
//!
//! `build.rs` generates the sources into `OUT_DIR` on every build, so there
//! is no golden file to keep in step. Not published: it is a check, left out
//! of `make publish-all`, the semver matrix and the coverage report.
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

#[cfg(test)]
mod tests {
    use super::fix44;
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
}
