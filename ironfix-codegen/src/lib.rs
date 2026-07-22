/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Codegen
//!
//! Build-time code generation for the IronFix FIX protocol engine.
//!
//! This crate generates Rust source code from a loaded
//! `ironfix_dictionary::Dictionary`, producing type-safe field constants and
//! message structs. FIX `Price`, `Qty` and `Percentage` fields are generated as
//! `rust_decimal::Decimal`, never `f64`.
//!
//! ## Usage
//!
//! Intended for a `build.rs` script that generates code at compile time.
//!
//! No crate in this workspace consumes the generated output yet — the
//! generator is exercised only by its own unit tests, so treat the emitted
//! source as unproven against a real build.

pub mod generator;

pub use generator::{CodeGenerator, GeneratorConfig};
