/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! Rewrites the golden file the generated-code test compiles.
//!
//! Lives in its own target so it still builds when `golden/sample.rs` is stale
//! or empty — which is exactly when it is needed.

mod common;

/// Rewrites `golden/sample.rs` from the current generator.
///
/// Ignored by default: it is a maintenance action, not a check.
#[test]
#[ignore = "regenerates the golden file rather than checking it"]
fn test_regenerate_golden_file() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("sample.rs");
    if let Err(err) = std::fs::write(&path, common::generate_sample()) {
        panic!("could not write {}: {err}", path.display());
    }
}
