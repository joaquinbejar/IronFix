/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! Rewrites the golden files the generated-code test compiles.
//!
//! Lives in its own target so it still builds when a golden file is stale or
//! empty — which is exactly when it is needed.

mod common;

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

/// Rewrites `golden/sample.rs`, `golden/fix42.rs`, and `golden/fixt11.rs`
/// from the current generator.
///
/// Ignored by default: it is a maintenance action, not a check.
#[test]
#[ignore = "regenerates the golden files rather than checking them"]
fn test_regenerate_golden_file() {
    write_golden("sample.rs", &common::generate_sample());
    write_golden("fix42.rs", &common::generate_fix42());
    write_golden("fixt11.rs", &common::generate_fixt11());
}
