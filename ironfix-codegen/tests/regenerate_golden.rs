/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! Rewrites the golden files the generated-code tests compile.
//!
//! Lives in its own target so it still builds when a golden file is stale or
//! empty — which is exactly when it is needed.

mod common;
mod std_names_common;
mod views_common;

/// Writes `code` to `tests/golden/<file>`, failing the test on an I/O error.
#[track_caller]
fn write_golden(file: &str, code: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(file);
    if let Err(err) = std::fs::write(&path, code) {
        panic!("could not write {}: {err}", path.display());
    }
}

/// Rewrites every golden file from the current generator: the default
/// output (`sample.rs`, `fix42.rs`, `fixt11.rs`, `std_names.rs`) and the
/// views (`views_sample.rs`, `views_fix44_order.rs`, `views_fixt11.rs`,
/// `views_std_names.rs`).
///
/// Ignored by default: it is a maintenance action, not a check.
#[test]
#[ignore = "regenerates the golden files rather than checking them"]
fn test_regenerate_golden_file() {
    write_golden("sample.rs", &common::generate_sample());
    write_golden("fix42.rs", &common::generate_fix42());
    write_golden("fixt11.rs", &common::generate_fixt11());
    write_golden("views_sample.rs", &views_common::generate_views_sample());
    write_golden(
        "views_fix44_order.rs",
        &views_common::generate_views_fix44_order(),
    );
    write_golden("views_fixt11.rs", &views_common::generate_views_fixt11());
    write_golden("std_names.rs", &std_names_common::generate_std_names());
    write_golden(
        "views_std_names.rs",
        &std_names_common::generate_views_std_names(),
    );
}
