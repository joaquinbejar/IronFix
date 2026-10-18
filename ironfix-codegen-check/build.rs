/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Generates the views of the embedded FIX 4.4, FIX 4.2 and FIXT 1.1
//! dictionaries into `OUT_DIR`, for `src/lib.rs` to include.
//!
//! The `cargo::` lines are build-script directives to Cargo, which reads them
//! from standard output; they are not logging.

use ironfix_codegen::CodeGenerator;
use ironfix_dictionary::{Dictionary, DictionaryError};
use std::error::Error;
use std::path::PathBuf;

/// Loads one embedded dictionary.
type Loader = fn() -> Result<&'static Dictionary, DictionaryError>;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-changed=build.rs");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let generator = CodeGenerator::new();
    let dictionaries: [(&str, Loader); 3] = [
        ("fix44", Dictionary::fix44),
        ("fix42", Dictionary::fix42),
        ("fixt11", Dictionary::fixt11),
    ];
    for (name, load) in dictionaries {
        let views = generator.generate_views(load()?)?;
        std::fs::write(out_dir.join(format!("{name}_views.rs")), views)?;
    }
    Ok(())
}
