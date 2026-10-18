/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Generates into `OUT_DIR`, for `src/lib.rs` to include:
//!
//! - the views of the embedded FIX 4.4, FIX 4.2 and FIXT 1.1 dictionaries;
//! - the default output and the views of the dictionary loaded from the
//!   FIX Trading Community's FIX 4.4 Orchestra repository, the
//!   `ironfix-dictionary` test fixture (which is not published, like this
//!   crate).
//!
//! The `cargo::` lines are build-script directives to Cargo, which reads them
//! from standard output; they are not logging.

use ironfix_codegen::CodeGenerator;
use ironfix_dictionary::{Dictionary, DictionaryError};
use std::error::Error;
use std::path::PathBuf;

/// Loads one embedded dictionary.
type Loader = fn() -> Result<&'static Dictionary, DictionaryError>;

/// The FIX 4.4 Orchestra repository, relative to this crate.
const ORCHESTRA_FIX44: &str = "../ironfix-dictionary/tests/fixtures/orchestra/OrchestraFIX44.xml";

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed={ORCHESTRA_FIX44}");
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

    let orchestra = Dictionary::from_orchestra_xml(&std::fs::read_to_string(ORCHESTRA_FIX44)?)?;
    let dict = orchestra.dictionary();
    std::fs::write(
        out_dir.join("orchestra_fix44.rs"),
        generator.generate(dict)?,
    )?;
    std::fs::write(
        out_dir.join("orchestra_fix44_views.rs"),
        generator.generate_views(dict)?,
    )?;
    Ok(())
}
