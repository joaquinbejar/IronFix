/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Codegen
//!
//! Build-time code generation for the IronFix FIX protocol engine.
//!
//! This crate turns a loaded `ironfix_dictionary::Dictionary` into Rust
//! source: one `u32` constant per field tag, and one struct per message
//! (including the fields its components contribute and a struct per repeating
//! group entry). FIX `Price`, `Qty` and `Percentage` fields are generated as
//! `rust_decimal::Decimal`, never `f64`.
//!
//! The generated structs are **data definitions only** — they carry no
//! `FixMessage` or `FixField` implementation, and nothing in the IronFix
//! workspace consumes this crate today.
//!
//! ## Usage
//!
//! Typically used in a `build.rs` script to generate code at compile time:
//!
//! ```no_run
//! use ironfix_codegen::CodeGenerator;
//! use ironfix_dictionary::Dictionary;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let code = CodeGenerator::new().generate(Dictionary::fix44()?)?;
//! std::fs::write("fix44.rs", code)?;
//! # Ok(())
//! # }
//! ```
//!
//! The generated file is written with `//` line comments rather than an inner
//! `//!` header, so it can be `include!`d inside a module.
//!
//! Generation **fails closed**: a dictionary that references a field or
//! component it does not define, or a component that contains itself, is a
//! [`GeneratorError`] rather than a struct silently missing a field.

pub mod generator;

pub use generator::{CodeGenerator, GeneratorConfig, GeneratorError};
