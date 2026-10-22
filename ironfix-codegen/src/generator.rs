/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Code generator for FIX dictionaries.
//!
//! Generates Rust source code from a loaded [`Dictionary`]: one `u32` constant
//! per field tag, and one struct per message, per component and per
//! repeating-group definition ([`CodeGenerator::generate`]); and, opt-in and
//! in a separate file, borrowed views, enumerations and writers
//! ([`CodeGenerator::generate_views`]).
//!
//! # What the default output contains
//!
//! ```text
//! // Generated FIX.4.4 definitions.
//!
//! pub type FixDecimal = ::rust_decimal::Decimal;
//!
//! /// Field tag constants.
//! pub mod fields {
//!     /// ClOrdID (tag 11).
//!     pub const CL_ORD_ID: u32 = 11;
//! }
//!
//! /// Message type definitions, ...
//! pub mod messages {
//!     use super::FixDecimal;
//!
//!     /// NewOrderSingle message (MsgType=D).
//!     #[derive(Debug, Clone)]
//!     pub struct NewOrderSingle {
//!         /// ClOrdID (tag 11).
//!         pub cl_ord_id: ::std::string::String,
//!         /// Parties component.
//!         pub parties: ::core::option::Option<super::components::Parties>,
//!         /// Instrument component.
//!         pub instrument: super::components::Instrument,
//!         /// Price (tag 44).
//!         pub price: ::core::option::Option<FixDecimal>,
//!     }
//! }
//!
//! /// Component type definitions, ...
//! pub mod components {
//!     /// Parties component, one type shared by every message, ...
//!     #[derive(Debug, Clone)]
//!     pub struct Parties {
//!         /// NoPartyIDs (tag 453) repeating group; its length is the count field.
//!         pub no_party_ids: ::core::option::Option<::std::vec::Vec<PartiesNoPartyIDsEntry>>,
//!     }
//!
//!     /// One entry of the NoPartyIDs (tag 453) repeating group in Parties.
//!     #[derive(Debug, Clone)]
//!     pub struct PartiesNoPartyIDsEntry {
//!         /// PartyID (tag 448).
//!         pub party_id: ::core::option::Option<::std::string::String>,
//!         /// PtysSubGrp component.
//!         pub ptys_sub_grp: ::core::option::Option<PtysSubGrp>,
//!     }
//! }
//! ```
//!
//! Each definition is generated once and referenced by name (see
//! `doc/adr/0019-shared-component-and-group-types-in-the-default-output.md`):
//! a component is one struct in `components`, a repeating group one entry
//! struct `<DeclaringOwner><GroupName>Entry` next to its declaring message,
//! component or entry, and a struct lists its members in XML order
//! (`members()`). The file header is written with `//` line comments rather
//! than `//!`, so the output can be `include!`d inside a module — the usual
//! `build.rs` + `OUT_DIR` workflow, where an inner attribute would be
//! rejected.
//!
//! # What it does not contain
//!
//! The structs of [`CodeGenerator::generate`] are **data definitions only**:
//! no `FixMessage` implementations, no encode/decode. Reading and writing
//! typed fields is what the opt-in [`CodeGenerator::generate_views`] output
//! is for (borrowed views, enumerations, static group layouts and writers; see
//! `doc/adr/0012-generated-views-enums-and-writers.md`). Nothing in this
//! workspace consumes either output.
//!
//! # Fidelity limits of the default output, stated rather than hidden
//!
//! - **Requiredness is per definition.** A field required inside a component
//!   or a group entry is a bare type in that component's or entry's struct;
//!   whether the component or group itself is present is the `Option` around
//!   the field that references it. Nothing enforces a field that FIX makes
//!   conditionally required.
//! - **A tag a message reaches twice is two struct fields.** A message that
//!   lists a field and a component carrying the same tag has one in each
//!   struct; the data structs do not decide which one a wire value belongs
//!   to.
//! - **No validation.** The structs are validated by nothing here;
//!   conformance checking is `ironfix_dictionary::Validator`.

use ironfix_dictionary::schema::{Dictionary, FieldDef, FieldType};
use std::collections::HashSet;
use thiserror::Error;

/// Name of the generated alias for the decimal type.
///
/// Emitted once per file as `pub type FixDecimal = rust_decimal::Decimal;`, so
/// every FIX `Price` / `Qty` / `Amt` / `Percentage` field resolves to
/// `rust_decimal::Decimal` through a single declaration — and never to
/// `f64`.
pub(crate) const DECIMAL_ALIAS: &str = "FixDecimal";

/// Rust keywords that cannot be written as raw identifiers (`r#...`).
const NON_RAW_KEYWORDS: [&str; 4] = ["crate", "self", "Self", "super"];

/// Deepest component-and-group nesting the generator will expand.
///
/// A [`Dictionary`] is untrusted input, and its structure can be built by hand
/// (every schema type is `pub` with `pub` fields), bypassing the loader's own
/// `MAX_COMPONENT_DEPTH` guard. A cycle that closes across a group boundary is
/// reported precisely as [`GeneratorError::ComponentCycle`]; this ceiling is the
/// backstop for the other pathological case — a chain that nests ever deeper
/// without ever repeating a name — so a hand-built dictionary yields
/// [`GeneratorError::MaxDepthExceeded`] instead of overflowing the stack. It
/// matches the loader's `MAX_COMPONENT_DEPTH`.
pub(crate) const MAX_NESTING_DEPTH: usize = 32;

/// Rust keywords, strict and reserved, that a FIX field name can collide with.
///
/// `Yield` (tag 236) is the collision that exists in the vendored FIX 4.4
/// dictionary: it lowercases to `yield`, a reserved keyword, and is emitted as
/// `r#yield`.
const KEYWORDS: [&str; 51] = [
    "as", "async", "await", "become", "box", "break", "const", "continue", "crate", "do", "dyn",
    "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if", "impl", "in", "let",
    "loop", "macro", "match", "mod", "move", "mut", "override", "priv", "pub", "ref", "return",
    "self", "static", "struct", "super", "trait", "true", "try", "type", "typeof", "unsafe",
    "unsized", "use", "virtual", "where", "while", "yield", "Self",
];

/// Reasons a dictionary cannot be turned into Rust source.
///
/// Every variant is a dictionary that refers to something it does not define,
/// or defines something that has no Rust form. The generator reports these
/// instead of silently omitting the offending item — a struct quietly missing
/// its price field is worse than a build failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GeneratorError {
    /// A message, component, or group references a tag the dictionary does not
    /// define, so the field's type is unknown.
    #[error("{scope} references tag {tag}, which the dictionary does not define")]
    UnknownField {
        /// The referenced tag.
        tag: u32,
        /// What referenced it, for example `message NewOrderSingle`.
        scope: String,
    },

    /// A message, component, or group references a component the dictionary
    /// does not define.
    #[error("{scope} references component '{name}', which the dictionary does not define")]
    UnknownComponent {
        /// The referenced component name.
        name: String,
        /// What referenced it.
        scope: String,
    },

    /// A component contains itself, directly, through other components, or
    /// through the entries of a repeating group it declares.
    ///
    /// Expanding it would not terminate; the cycle is reported with the path
    /// that closes it.
    #[error("component '{name}' contains itself: {path}")]
    ComponentCycle {
        /// The component that closes the cycle.
        name: String,
        /// The expansion path, joined with ` -> `.
        path: String,
    },

    /// A dictionary item has a name with no usable Rust identifier.
    #[error("{what} '{name}' has no usable Rust identifier")]
    UnnameableItem {
        /// The kind of item, for example `field` or `message`.
        what: &'static str,
        /// The offending name.
        name: String,
    },

    /// Components and groups nested deeper than `MAX_NESTING_DEPTH` without
    /// closing a cycle.
    ///
    /// A dictionary this deep is treated as pathological rather than expanded,
    /// so a hand-built dictionary that escaped the loader's guard cannot
    /// overflow the stack. A genuine cycle is reported as
    /// [`GeneratorError::ComponentCycle`]; this is the backstop for a deep but
    /// acyclic chain.
    #[error("{scope} nests components and groups deeper than the limit of {limit}")]
    MaxDepthExceeded {
        /// What was being expanded when the limit was reached.
        scope: String,
        /// The nesting-depth ceiling.
        limit: usize,
    },

    /// A `data` (or `XMLData`) field has no `Length` field to frame it.
    ///
    /// Raised by [`CodeGenerator::generate_views`] only. The dictionary does
    /// not name LENGTH/DATA pairs; a `data` field is paired with the `Length`
    /// field listed immediately before it, as every pair of the embedded
    /// dictionaries is listed. A `data` field with no such field before it,
    /// or one that opens a repeating-group entry (where its length would have
    /// to come before the delimiter), cannot be written with its count, so a
    /// decoder would read any SOH in it as a field terminator. The generator
    /// refuses it rather than emit a writer that corrupts frames.
    #[error(
        "{scope}: data field {tag} is not immediately preceded by the length field that frames it"
    )]
    UnpairedDataField {
        /// The `data` field's tag.
        tag: u32,
        /// Where it is listed, for example `component Signature`.
        scope: String,
    },
}

/// Configuration for code generation.
#[derive(Debug, Clone)]
pub struct GeneratorConfig {
    /// Whether to generate the `fields` module of tag constants.
    pub generate_fields: bool,
    /// Whether to generate the `messages` module of message structs (and the
    /// `components` module, which only messages reach).
    pub generate_messages: bool,
    /// Whether to generate the `components` module, one struct per component
    /// a message reaches, and a field of that type in every message,
    /// component and group entry that lists the component.
    ///
    /// With this off, a generated struct carries only the fields and groups
    /// its definition lists directly — for FIX 4.4 that leaves
    /// `NewOrderSingle` without `Symbol` (55), which lives in the `Instrument`
    /// component. It is on by default.
    pub generate_components: bool,
    /// Module visibility (e.g., `"pub"`, `"pub(crate)"`).
    pub visibility: String,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            generate_fields: true,
            generate_messages: true,
            generate_components: true,
            visibility: "pub".to_string(),
        }
    }
}

/// Code generator for FIX dictionaries.
#[derive(Debug)]
pub struct CodeGenerator {
    /// What to emit, and with what visibility.
    config: GeneratorConfig,
}

impl CodeGenerator {
    /// Creates a new code generator with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: GeneratorConfig::default(),
        }
    }

    /// Creates a new code generator with the specified configuration.
    #[must_use]
    pub fn with_config(config: GeneratorConfig) -> Self {
        Self { config }
    }

    /// Returns the configuration this generator was built with.
    #[must_use]
    pub const fn config(&self) -> &GeneratorConfig {
        &self.config
    }

    /// Generates Rust source code from a dictionary.
    ///
    /// The source has a `fields` module of tag constants, a `messages`
    /// module with one struct per message, and a `components` module with one
    /// struct per component a message reaches (when one does). Each component
    /// and each repeating-group definition is generated once and referenced
    /// by name from every message, component and group entry that uses it; a
    /// group's entry struct is `<DeclaringOwner><GroupName>Entry`, for
    /// example `PartiesNoPartyIDsEntry`. Members are listed in XML order.
    ///
    /// # Arguments
    /// * `dict` - The FIX dictionary to generate code from
    ///
    /// # Errors
    /// Returns [`GeneratorError`] if the dictionary references a field or
    /// component it does not define, if a component contains itself, if
    /// components and groups nest past the depth limit, or if a name has no
    /// Rust identifier (`what` is then `field`, `message`, `group` or
    /// `component`). The generator never drops such an item silently.
    pub fn generate(&self, dict: &Dictionary) -> Result<String, GeneratorError> {
        let mut code = String::new();

        line(
            &mut code,
            &format!("// Generated {} definitions.", dict.version),
        );
        line(&mut code, "//");
        line(
            &mut code,
            "// This file was generated by ironfix-codegen. Do not edit.",
        );
        line(&mut code, "");

        let model = if self.config.generate_messages {
            crate::structs::build(dict, self.config.generate_components)?
        } else {
            crate::structs::DataModel::default()
        };
        let uses_decimal = model.uses_decimal();

        if uses_decimal {
            line(
                &mut code,
                "/// Decimal type for FIX price, quantity, and amount fields.",
            );
            line(
                &mut code,
                &format!(
                    "{} type {DECIMAL_ALIAS} = ::rust_decimal::Decimal;",
                    self.config.visibility
                ),
            );
            line(&mut code, "");
        }

        if self.config.generate_fields {
            self.emit_fields_module(&mut code, dict)?;
        }

        if self.config.generate_messages {
            crate::structs::emit(&mut code, &self.config.visibility, &model);
        }

        Ok(code)
    }

    /// Generates borrowed views, enumerations and writers from a dictionary.
    ///
    /// Opt-in and separate from [`CodeGenerator::generate`], whose output it
    /// does not change: the returned source is a second, self-contained file
    /// with four modules.
    ///
    /// - `enums`: one enumeration per field with declared values that a view
    ///   or writer uses, with an `Other(&[u8])` variant so an undeclared wire
    ///   value is still readable. Multi-value fields read and write as tokens.
    /// - `layouts`: one `ironfix_dictionary::GroupSpec` constant per
    ///   repeating-group definition and one `ironfix_dictionary::GroupSet`
    ///   constant per message, built at compile time, so reading needs no
    ///   dictionary at run time.
    /// - `views`: one `XxxView<'m, 'a>` per message over a decoded
    ///   `ironfix_core::message::RawMessage`, and one view type per group
    ///   definition (shared by every message that uses it), with typed
    ///   accessors that borrow the decoded buffer and check each value
    ///   against its FIX type's grammar, as the validator does.
    /// - `writers`: one `XxxFields<'v>` per message and group definition,
    ///   whose `write` checks every value and then sends the body in XML
    ///   order (an entry: its delimiter first) to a generated
    ///   `writers::Sink`: any
    ///   `FnMut(u32, &[u8])` closure is one, and a target that frames
    ///   LENGTH/DATA pairs itself (`ironfix_tagvalue::Encoder`,
    ///   `ironfix_engine::OutboundMessage`) implements it.
    ///
    /// The generated code depends on the `ironfix-core`, `rust_decimal` and
    /// `ironfix-dictionary` `^0.6` crates (it calls `GroupSet::field`,
    /// `GroupSet::with_level_tags` and `FieldType::is_valid_value`), and contains no
    /// `#[allow]`. Only [`GeneratorConfig::visibility`] applies: components
    /// are always expanded, because a view must know every group of a
    /// message to tell a message-level field from one inside a group.
    ///
    /// # Errors
    /// Returns [`GeneratorError`] under the same fail-closed rules as
    /// [`CodeGenerator::generate`]: an undefined field or component, a
    /// component cycle, nesting past the depth limit, or a name with no Rust
    /// identifier (`what` is then `field`, `message`, `group` or
    /// `component`); and [`GeneratorError::UnpairedDataField`] for a `data`
    /// field not listed right after its `Length` field, or opening a group
    /// entry.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ironfix_codegen::CodeGenerator;
    /// use ironfix_dictionary::Dictionary;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let views = CodeGenerator::new().generate_views(Dictionary::fix44()?)?;
    /// std::fs::write("fix44_views.rs", views)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate_views(&self, dict: &Dictionary) -> Result<String, GeneratorError> {
        crate::views::generate(dict, &self.config.visibility)
    }

    /// Emits the `fields` module of tag constants, sorted by tag.
    fn emit_fields_module(
        &self,
        code: &mut String,
        dict: &Dictionary,
    ) -> Result<(), GeneratorError> {
        let mut fields: Vec<&FieldDef> = dict.fields().collect();
        fields.sort_by_key(|field| field.tag);

        line(code, "/// Field tag constants.");
        line(code, &format!("{} mod fields {{", self.config.visibility));

        let mut used: HashSet<String> = HashSet::with_capacity(fields.len());
        for field in fields {
            let base = to_screaming_snake_case(&field.name);
            if !is_valid_ident(&base) {
                return Err(GeneratorError::UnnameableItem {
                    what: "field",
                    name: field.name.clone(),
                });
            }
            // Two field names can collapse onto one constant name; the tag
            // disambiguates them rather than one silently shadowing the other.
            let name = unique_name(&mut used, &base, field.tag);

            line(code, &format!("    /// {}", field_doc(field)));
            line(code, &format!("    pub const {name}: u32 = {};", field.tag));
        }

        line(code, "}");
        line(code, "");
        Ok(())
    }
}

impl Default for CodeGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Appends `text` and a newline to `code`.
pub(crate) fn line(code: &mut String, text: &str) {
    code.push_str(text);
    code.push('\n');
}

/// Wraps `ty` in `Option<...>` unless the field is required.
pub(crate) fn wrap_optional(ty: &str, required: bool) -> String {
    if required {
        ty.to_string()
    } else {
        format!("::core::option::Option<{ty}>")
    }
}

/// Builds the doc line for a field definition.
pub(crate) fn field_doc(field: &FieldDef) -> String {
    let mut doc = format!("{} (tag {}).", field.name, field.tag);
    if let Some(description) = &field.description {
        let flattened = description.replace(['\n', '\r'], " ");
        let trimmed = flattened.trim();
        if !trimmed.is_empty() {
            doc.push(' ');
            doc.push_str(trimmed);
        }
    }
    doc
}

/// Resolves a struct field identifier that is unique within its struct.
///
/// Two FIX field names can collapse onto one Rust identifier (`ClOrdID` and
/// `ClOrdId` both snake-case to `cl_ord_id`); the tag disambiguates them, and a
/// numeric suffix settles the remaining pathological case. Nothing is ever
/// dropped to avoid a clash. Uniqueness is checked on the escaped identifier
/// (see [`claim_ident`]), so `Crate` (`crate_`) and `Crate_` do not collide.
///
/// # Errors
///
/// [`GeneratorError::UnnameableItem`] if the name is not an identifier in
/// snake case, or if no unique identifier is left for it.
pub(crate) fn resolve_field_name(
    used: &mut HashSet<String>,
    name: &str,
    tag: u32,
) -> Result<String, GeneratorError> {
    let base = to_snake_case(name);
    if !is_valid_ident(&base) {
        return Err(GeneratorError::UnnameableItem {
            what: "field",
            name: name.to_string(),
        });
    }
    claim_ident(used, &base, &tag.to_string()).ok_or_else(|| GeneratorError::UnnameableItem {
        what: "field",
        name: name.to_string(),
    })
}

/// Claims, in `used`, a value identifier (a struct field or an accessor)
/// for `base`: `base`, then `base` qualified by `qualifier` (a tag, or a
/// word such as `component`), then that followed by `2`, `3`, ...
///
/// Each candidate is escaped with [`to_field_ident`] *before* it is checked
/// and reserved, and `used` holds escaped identifiers only. Escaping can
/// fold two names onto one identifier (`crate` becomes `crate_`, the plain
/// snake case of `Crate_`; `self` becomes `self_`), so checking the
/// unescaped candidate would hand the same identifier out twice. Suffixes are
/// joined with one underscore, or none after a trailing one ([`join_ident`]),
/// so no identifier holds `__`, which `non_snake_case` rejects.
///
/// Returns `None` only if the numeric suffix runs out of `usize` values;
/// each taken identifier blocks at most one candidate, so it never does.
#[must_use]
pub(crate) fn claim_ident(
    used: &mut HashSet<String>,
    base: &str,
    qualifier: &str,
) -> Option<String> {
    let mut claim = |candidate: &str| {
        let ident = to_field_ident(candidate);
        used.insert(ident.clone()).then_some(ident)
    };
    if let Some(ident) = claim(base) {
        return Some(ident);
    }
    let qualified = join_ident(base, qualifier);
    if let Some(ident) = claim(&qualified) {
        return Some(ident);
    }
    let mut suffix = 2usize;
    loop {
        if let Some(ident) = claim(&join_ident(&qualified, &suffix.to_string())) {
            return Some(ident);
        }
        suffix = suffix.checked_add(1)?;
    }
}

/// Joins `suffix` to the identifier `base` with one underscore, or with
/// none when `base` already ends with one (`self_` and `5` give `self_5`,
/// never `self__5`).
#[must_use]
pub(crate) fn join_ident(base: &str, suffix: &str) -> String {
    if base.ends_with('_') {
        format!("{base}{suffix}")
    } else {
        format!("{base}_{suffix}")
    }
}

/// Returns a name not already in `used`, disambiguating first by `tag` and
/// then by a numeric suffix.
pub(crate) fn unique_name(used: &mut HashSet<String>, base: &str, tag: u32) -> String {
    if used.insert(base.to_string()) {
        return base.to_string();
    }
    let with_tag = format!("{base}_{tag}");
    if used.insert(with_tag.clone()) {
        return with_tag;
    }
    let mut suffix = 2usize;
    loop {
        let candidate = format!("{with_tag}_{suffix}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
        suffix += 1;
    }
}

/// Returns a type name not already used in the generated module.
///
/// The numeric suffix is joined with [`join_type`], so an escaped candidate
/// (`Self_`) continues as `Self2`, never `Self_2`, which
/// `non_camel_case_types` rejects.
pub(crate) fn unique_type_name(used: &mut HashSet<String>, candidate: &str) -> String {
    if used.insert(candidate.to_string()) {
        return candidate.to_string();
    }
    let mut suffix = 2usize;
    loop {
        let name = join_type(candidate, &suffix.to_string());
        if used.insert(name.clone()) {
            return name;
        }
        suffix += 1;
    }
}

/// Appends `suffix` to the type name `stem`, dropping the trailing
/// underscores that escape a keyword (`Self_` and `View` give `SelfView`),
/// so the result never has an underscore next to a letter, which
/// `non_camel_case_types` rejects. The result ends with `suffix`, so it is
/// not a keyword. A stem made only of underscores is kept whole.
#[must_use]
pub(crate) fn join_type(stem: &str, suffix: &str) -> String {
    let trimmed = stem.trim_end_matches('_');
    let stem = if trimmed.is_empty() { stem } else { trimmed };
    format!("{stem}{suffix}")
}

/// Returns true if `name` is a Rust keyword.
pub(crate) fn is_keyword(name: &str) -> bool {
    KEYWORDS.contains(&name)
}

/// Escapes a value identifier that collides with a Rust keyword.
///
/// A keyword becomes a raw identifier (`yield` -> `r#yield`); the four
/// keywords that cannot be written raw take a trailing underscore instead.
pub(crate) fn to_field_ident(name: &str) -> String {
    if NON_RAW_KEYWORDS.contains(&name) {
        return format!("{name}_");
    }
    if is_keyword(name) {
        return format!("r#{name}");
    }
    name.to_string()
}

/// Escapes a type identifier that collides with a Rust keyword.
///
/// Type positions cannot use `r#Self`, so a collision takes a trailing
/// underscore.
pub(crate) fn to_type_ident(name: &str) -> String {
    if is_keyword(name) {
        return format!("{name}_");
    }
    name.to_string()
}

/// Returns true when `ident` is a valid Rust identifier: a leading ASCII
/// letter or underscore, then only ASCII letters, digits, or underscores.
///
/// The case converters split words but preserve any other byte, so a
/// dictionary name carrying a hyphen, space, or dot survives conversion into a
/// string that is not a legal identifier. A [`Dictionary`] is untrusted,
/// possibly hand-built input, so such a name is rejected as a typed
/// [`GeneratorError::UnnameableItem`] rather than emitted as
/// `pub const FOO-BAR: u32` that will not compile.
pub(crate) fn is_valid_ident(ident: &str) -> bool {
    let mut chars = ident.chars();
    let starts_valid = matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic());
    starts_valid && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Converts a string to `SCREAMING_SNAKE_CASE`.
pub(crate) fn to_screaming_snake_case(s: &str) -> String {
    let mut result = String::new();
    let mut prev_lower = false;

    for c in s.chars() {
        if c.is_uppercase() && prev_lower {
            result.push('_');
        }
        result.push(c.to_ascii_uppercase());
        prev_lower = c.is_lowercase();
    }

    result
}

/// Converts a string to `snake_case`.
pub(crate) fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    let mut prev_lower = false;

    for c in s.chars() {
        if c.is_uppercase() && prev_lower {
            result.push('_');
        }
        result.push(c.to_ascii_lowercase());
        prev_lower = c.is_lowercase();
    }

    result
}

/// Converts a string to `PascalCase`.
pub(crate) fn to_pascal_case(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = true;

    for c in s.chars() {
        if c == '_' || c == ' ' {
            capitalize_next = true;
        } else if capitalize_next {
            result.push(c.to_ascii_uppercase());
            capitalize_next = false;
        } else {
            result.push(c);
        }
    }

    result
}

/// Maps a FIX field type to the Rust type the generator emits for it.
///
/// Every monetary or quantity type maps to [`DECIMAL_ALIAS`], never to `f64`:
/// binary floating point cannot represent a price exactly.
pub(crate) fn field_type_to_rust(field_type: FieldType) -> &'static str {
    match field_type {
        FieldType::Int
        | FieldType::Length
        | FieldType::SeqNum
        | FieldType::NumInGroup
        | FieldType::TagNum
        | FieldType::DayOfMonth => "i64",
        FieldType::Float
        | FieldType::Qty
        | FieldType::Price
        | FieldType::PriceOffset
        | FieldType::Amt
        | FieldType::Percentage => DECIMAL_ALIAS,
        FieldType::Char => "char",
        FieldType::Boolean => "bool",
        FieldType::String
        | FieldType::MultipleCharValue
        | FieldType::MultipleStringValue
        | FieldType::Country
        | FieldType::Currency
        | FieldType::Exchange
        | FieldType::Language
        | FieldType::Pattern
        | FieldType::Tenor
        | FieldType::MonthYear
        | FieldType::UtcTimestamp
        | FieldType::UtcTimeOnly
        | FieldType::UtcDateOnly
        | FieldType::LocalMktDate
        | FieldType::LocalMktTime
        | FieldType::TzTimeOnly
        | FieldType::TzTimestamp
        | FieldType::Reserved => "::std::string::String",
        FieldType::Data | FieldType::XmlData => "::std::vec::Vec<u8>",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // `FieldRef` also names a zero-copy wire field in `ironfix-core`; this is
    // the schema-side one (tag, name, required).
    use ironfix_dictionary::schema::FieldRef as SchemaFieldRef;
    use ironfix_dictionary::schema::Member as SchemaMember;
    use ironfix_dictionary::schema::{
        ComponentDef, ComponentRef, GroupDef, MessageCategory, MessageDef, Version,
    };

    /// The QuickFIX FIX 4.4 dictionary, a test fixture of
    /// `ironfix-dictionary` (`tests/fixtures/quickfix`, not published). Its
    /// components (Parties, Instrument, PreAllocGrp, ...) exercise the
    /// component paths of the generator, which the embedded FIX Orchestra
    /// dictionary, holding most blocks as groups, reaches less.
    fn fix44() -> &'static Dictionary {
        static FIX44: std::sync::OnceLock<Dictionary> = std::sync::OnceLock::new();
        FIX44.get_or_init(|| {
            match Dictionary::from_quickfix_xml(include_str!(
                "../../ironfix-dictionary/tests/fixtures/quickfix/FIX44.xml"
            )) {
                Ok(dict) => dict,
                Err(err) => panic!("the QuickFIX FIX 4.4 fixture must load: {err}"),
            }
        })
    }

    /// Generates from `dict`, failing the test with the generator error.
    #[track_caller]
    fn generate(generator: &CodeGenerator, dict: &Dictionary) -> String {
        match generator.generate(dict) {
            Ok(code) => code,
            Err(err) => panic!("generation must succeed: {err}"),
        }
    }

    #[test]
    fn test_to_screaming_snake_case() {
        assert_eq!(to_screaming_snake_case("MsgType"), "MSG_TYPE");
        assert_eq!(to_screaming_snake_case("ClOrdID"), "CL_ORD_ID");
        assert_eq!(to_screaming_snake_case("BeginString"), "BEGIN_STRING");
    }

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("MsgType"), "msg_type");
        assert_eq!(to_snake_case("ClOrdID"), "cl_ord_id");
        assert_eq!(to_snake_case("NoPartyIDs"), "no_party_ids");
    }

    #[test]
    fn test_to_pascal_case() {
        assert_eq!(to_pascal_case("new_order_single"), "NewOrderSingle");
        assert_eq!(to_pascal_case("execution_report"), "ExecutionReport");
    }

    #[test]
    fn test_claim_ident_checks_and_reserves_the_escaped_identifier() {
        // `crate` escapes to `crate_`, the plain snake case of `Crate_`: in
        // either order, the second claim is qualified, never a duplicate.
        let mut used = HashSet::new();
        assert_eq!(
            claim_ident(&mut used, "crate_", "6001").as_deref(),
            Some("crate_")
        );
        assert_eq!(
            claim_ident(&mut used, "crate", "6002").as_deref(),
            Some("crate_6002")
        );
        let mut used = HashSet::new();
        assert_eq!(
            claim_ident(&mut used, "crate", "6002").as_deref(),
            Some("crate_")
        );
        assert_eq!(
            claim_ident(&mut used, "crate_", "6001").as_deref(),
            Some("crate_6001")
        );
        // Same for `self` and `Self_`, qualified by a word.
        let mut used = HashSet::new();
        assert_eq!(
            claim_ident(&mut used, "self", "component").as_deref(),
            Some("self_")
        );
        assert_eq!(
            claim_ident(&mut used, "self_", "component").as_deref(),
            Some("self_component")
        );
        assert_eq!(
            claim_ident(&mut used, "self", "component").as_deref(),
            Some("self_component_2")
        );
        // A raw identifier is reserved as written.
        let mut used = HashSet::new();
        assert_eq!(
            claim_ident(&mut used, "yield", "236").as_deref(),
            Some("r#yield")
        );
        assert_eq!(
            claim_ident(&mut used, "yield", "237").as_deref(),
            Some("yield_237")
        );
        assert!(used.contains("r#yield"));
    }

    #[test]
    fn test_join_ident_and_join_type_leave_no_lint_breaking_underscore() {
        assert_eq!(join_ident("cl_ord_id", "12"), "cl_ord_id_12");
        // No `__`, which `non_snake_case` rejects.
        assert_eq!(join_ident("self_", "5"), "self_5");
        // No underscore next to a letter, which `non_camel_case_types` rejects.
        assert_eq!(join_type("Self_", "View"), "SelfView");
        assert_eq!(join_type("Self_", "2"), "Self2");
        assert_eq!(join_type("Parties", "NoPartyIDs"), "PartiesNoPartyIDs");
        assert_eq!(join_type("_", "X"), "_X");
        let mut used = HashSet::new();
        assert_eq!(unique_type_name(&mut used, "Self_"), "Self_");
        assert_eq!(unique_type_name(&mut used, "Self_"), "Self2");
    }

    #[test]
    fn test_to_field_ident_escapes_keywords() {
        assert_eq!(to_field_ident("yield"), "r#yield");
        assert_eq!(to_field_ident("type"), "r#type");
        assert_eq!(to_field_ident("match"), "r#match");
        // These four have no raw form.
        assert_eq!(to_field_ident("self"), "self_");
        assert_eq!(to_field_ident("crate"), "crate_");
        // Everything else is untouched.
        assert_eq!(to_field_ident("cl_ord_id"), "cl_ord_id");
    }

    #[test]
    fn test_generator_new_enables_every_section() {
        let generator = CodeGenerator::new();
        assert!(generator.config().generate_fields);
        assert!(generator.config().generate_messages);
        assert!(generator.config().generate_components);
    }

    #[test]
    fn test_generate_fix44_maps_price_and_qty_to_decimal() {
        let code = generate(&CodeGenerator::new(), fix44());
        assert!(code.contains("pub type FixDecimal = ::rust_decimal::Decimal;"));
        // Price (44) is listed on NewOrderSingle, OrderQty (38) in the
        // OrderQtyData component; both modules import the alias.
        let order = struct_body(&code, "NewOrderSingle");
        assert!(
            order.contains("pub price: ::core::option::Option<FixDecimal>,"),
            "{order}"
        );
        let qty = struct_body(&code, "OrderQtyData");
        assert!(
            qty.contains("pub order_qty: ::core::option::Option<FixDecimal>,"),
            "{qty}"
        );
        assert_eq!(code.matches("    use super::FixDecimal;").count(), 2);
        // A price must never be binary floating point.
        assert!(!code.contains("f64"));
        assert!(!code.contains("f32"));
    }

    #[test]
    fn test_generate_fix44_emits_the_keyword_field_as_a_raw_identifier() {
        let code = generate(&CodeGenerator::new(), fix44());
        // Yield (236) reaches YieldData -> the generated struct as r#yield.
        assert!(code.contains("pub r#yield:"));
        assert!(!code.contains("pub yield:"));
    }

    #[test]
    fn test_generate_fix44_wraps_optional_fields_and_leaves_required_bare() {
        let code = generate(&CodeGenerator::new(), fix44());
        // ClOrdID (11) is required in NewOrderSingle.
        assert!(code.contains("pub cl_ord_id: ::std::string::String,"));
        // Account (1) is optional there.
        assert!(code.contains("pub account: ::core::option::Option<::std::string::String>,"));
    }

    #[test]
    fn test_generate_fix44_new_order_single_references_its_components_by_type() {
        let code = generate(&CodeGenerator::new(), fix44());
        let body = struct_body(&code, "NewOrderSingle");
        // Instrument and OrderQtyData are required in NewOrderSingle, Parties
        // and PreAllocGrp are not: the reference decides the Option.
        assert!(
            body.contains("pub instrument: super::components::Instrument,"),
            "{body}"
        );
        assert!(
            body.contains("pub order_qty_data: super::components::OrderQtyData,"),
            "{body}"
        );
        assert!(
            body.contains("pub parties: ::core::option::Option<super::components::Parties>,"),
            "{body}"
        );
        assert!(
            body.contains(
                "pub pre_alloc_grp: ::core::option::Option<super::components::PreAllocGrp>,"
            ),
            "{body}"
        );
        assert!(body.contains("pub price:"), "{body}");
        // Symbol (55) is in the Instrument struct, not copied into the message.
        assert!(!body.contains("pub symbol:"), "{body}");
        let instrument = struct_body(&code, "Instrument");
        assert!(instrument.contains("pub symbol:"), "{instrument}");
    }

    #[test]
    fn test_generate_fix44_lists_members_in_xml_order() {
        let code = generate(&CodeGenerator::new(), fix44());
        // ADR-0016's case: the NoAllocs entry of PreAllocGrp lists the
        // NestedParties component before AllocQty (80).
        let entry = struct_body(&code, "PreAllocGrpNoAllocsEntry");
        let names: Vec<&str> = entry
            .lines()
            .filter_map(|text| text.trim_start().strip_prefix("pub "))
            .filter_map(|rest| rest.split_once(':').map(|(name, _)| name))
            .collect();
        assert_eq!(
            names,
            [
                "alloc_account",
                "alloc_acct_idsource",
                "alloc_settl_currency",
                "individual_alloc_id",
                "nested_parties",
                "alloc_qty"
            ]
        );
    }

    #[test]
    fn test_generate_fix44_emits_one_struct_per_repeating_group_definition() {
        let code = generate(&CodeGenerator::new(), fix44());
        // NoAllocs (78) reaches NewOrderSingle through PreAllocGrp: its entry
        // is named after the component that declares it.
        assert_eq!(
            code.matches("pub struct PreAllocGrpNoAllocsEntry {")
                .count(),
            1
        );
        assert!(code.contains("::std::vec::Vec<PreAllocGrpNoAllocsEntry>"));
        assert!(!code.contains("NewOrderSingleNoAllocsEntry"));
    }

    #[test]
    fn test_generate_fix44_component_used_by_several_messages_is_one_type() {
        let code = generate(&CodeGenerator::new(), fix44());
        assert_eq!(code.matches("pub struct Parties {").count(), 1);
        assert_eq!(
            code.matches("pub struct PartiesNoPartyIDsEntry {").count(),
            1
        );
        // Every message that lists Parties references the one type.
        let messages = messages_module(&code);
        let references = messages
            .matches("::core::option::Option<super::components::Parties>,")
            .count();
        assert!(references > 1, "Parties is referenced {references} times");
        // And no message carries its own copy of the party group.
        assert!(!messages.contains("NoPartyIDsEntry"));
    }

    #[test]
    fn test_generate_fix44_nests_groups_inside_components() {
        let code = generate(&CodeGenerator::new(), fix44());
        // Parties -> NoPartyIDs entry -> PtysSubGrp -> NoPartySubIDs entry.
        let entry = struct_body(&code, "PartiesNoPartyIDsEntry");
        assert!(
            entry.contains("pub ptys_sub_grp: ::core::option::Option<PtysSubGrp>,"),
            "{entry}"
        );
        let sub = struct_body(&code, "PtysSubGrp");
        assert!(
            sub.contains(
                "pub no_party_sub_ids: ::core::option::Option<::std::vec::Vec<PtysSubGrpNoPartySubIDsEntry>>,"
            ),
            "{sub}"
        );
        let sub_entry = struct_body(&code, "PtysSubGrpNoPartySubIDsEntry");
        assert!(sub_entry.contains("pub party_sub_id:"), "{sub_entry}");
    }

    #[test]
    fn test_generate_without_components_omits_component_fields() {
        let generator = CodeGenerator::with_config(GeneratorConfig {
            generate_components: false,
            ..GeneratorConfig::default()
        });
        let code = generate(&generator, fix44());
        let body = struct_body(&code, "NewOrderSingle");
        assert!(!body.contains("pub symbol:"), "{body}");
        assert!(!body.contains("pub instrument:"), "{body}");
        assert!(body.contains("pub cl_ord_id:"), "{body}");
        assert!(!code.contains("mod components"));
        assert!(!code.contains("super::components"));
    }

    #[test]
    fn test_generate_fix44_constant_names_are_unique() {
        let code = generate(&CodeGenerator::new(), fix44());
        let mut names: Vec<&str> = Vec::new();
        for text in code.lines() {
            let trimmed = text.trim_start();
            if let Some(rest) = trimmed.strip_prefix("pub const ")
                && let Some((name, _)) = rest.split_once(':')
            {
                names.push(name);
            }
        }
        assert_eq!(
            names.len(),
            fix44().fields().count(),
            "one constant per field"
        );
        let unique: HashSet<&&str> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "constant names must not collide");
    }

    /// Returns the names of the structs declared in `code`.
    fn struct_names(code: &str) -> Vec<&str> {
        code.lines()
            .filter_map(|text| text.trim_start().strip_prefix("pub struct "))
            .filter_map(|rest| rest.split_once(' ').map(|(name, _)| name))
            .collect()
    }

    #[test]
    fn test_generate_fix44_struct_names_are_unique_within_each_module() {
        let code = generate(&CodeGenerator::new(), fix44());
        for module in [messages_module(&code), components_module(&code)] {
            let names = struct_names(module);
            assert!(!names.is_empty());
            let unique: HashSet<&&str> = names.iter().collect();
            assert_eq!(unique.len(), names.len(), "struct names must not collide");
        }
    }

    #[test]
    fn test_generate_fix44_emits_one_struct_per_reached_component() {
        let code = generate(&CodeGenerator::new(), fix44());
        let components = components_module(&code);
        // Every struct of the module is a component or a group entry.
        let component_structs = struct_names(components)
            .into_iter()
            .filter(|name| fix44().get_component(name).is_some())
            .count();
        // FIX44.xml defines 104 components; no message lists `ExecsGrp` or
        // `Hop` (the header declares its NoHops group itself), so the other
        // 102 are generated, and those two are not.
        assert_eq!(fix44().components().count(), 104);
        assert_eq!(component_structs, 102);
        assert!(!components.contains("pub struct ExecsGrp {"));
        assert!(!components.contains("pub struct Hop {"));
    }

    #[test]
    fn test_generate_fix44_struct_fields_are_unique_within_each_struct() {
        let code = generate(&CodeGenerator::new(), fix44());
        let mut current: HashSet<String> = HashSet::new();
        for text in code.lines() {
            let trimmed = text.trim_start();
            if trimmed.starts_with("pub struct ") {
                current = HashSet::new();
            } else if let Some(rest) = trimmed.strip_prefix("pub ")
                && let Some((name, _)) = rest.split_once(':')
                && !rest.starts_with("const ")
                && !rest.starts_with("struct ")
                && !rest.starts_with("mod ")
                && !rest.starts_with("type ")
            {
                assert!(
                    current.insert(name.to_string()),
                    "field {name} is declared twice in one struct"
                );
            }
        }
    }

    #[test]
    fn test_generate_header_uses_line_comments_so_output_can_be_included() {
        let code = generate(&CodeGenerator::new(), fix44());
        // An inner attribute cannot appear in an `include!`d file.
        assert!(!code.contains("//!"));
        assert!(code.starts_with("// Generated FIX.4.4 definitions."));
    }

    #[test]
    fn test_generate_is_deterministic() {
        let generator = CodeGenerator::new();
        assert_eq!(generate(&generator, fix44()), generate(&generator, fix44()));
    }

    /// A dictionary with many messages and components, built afresh, so two
    /// calls hash their maps with different keys.
    fn many_definitions() -> Dictionary {
        let mut dict = Dictionary::new(Version::Fix44);
        for index in 0..40u32 {
            let tag = 5000 + index;
            dict.add_field(FieldDef::new(
                tag,
                format!("Field{index}"),
                FieldType::Price,
            ));
            dict.add_component(ComponentDef::new(
                format!("Comp{index}"),
                vec![field(tag, &format!("Field{index}"), index % 2 == 0)],
            ));
        }
        for index in 0..40u32 {
            dict.add_message(MessageDef::new(
                format!("U{index}"),
                format!("Message{index}"),
                MessageCategory::App,
                (0..5).map(|offset| {
                    component(&format!("Comp{}", (index + offset * 7) % 40), offset == 0)
                }),
            ));
        }
        dict
    }

    #[test]
    fn test_generate_is_deterministic_across_dictionary_instances() {
        // Messages and components live in `HashMap`s; the output must not
        // follow their iteration order.
        let generator = CodeGenerator::new();
        let first = generate(&generator, &many_definitions());
        let second = generate(&generator, &many_definitions());
        assert!(first == second, "two instances generate different text");
        let names = struct_names(components_module(&first));
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "components are ordered by name");
        assert_eq!(names.len(), 40);
    }

    #[test]
    fn test_generate_every_embedded_dictionary_is_deterministic_and_lint_clean() {
        let generator = CodeGenerator::new();
        for (loaded, what) in [
            (Dictionary::fix42(), "FIX 4.2"),
            (Dictionary::fix44(), "FIX 4.4"),
            (Dictionary::fixt11(), "FIXT 1.1"),
            (Dictionary::fix50sp2(), "FIX 5.0 SP2"),
        ] {
            let dict = embedded(loaded, what);
            let code = generate(&generator, dict);
            assert!(
                code == generate(&generator, dict),
                "{what} is deterministic"
            );
            assert!(!code.contains("#[allow"), "{what}: no #[allow]");
            assert!(!code.contains("//!"), "{what}: include!-able");
            // Token-wise, so a name merely containing the letters passes.
            assert!(
                !code
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .any(|token| token == "f64" || token == "f32"),
                "{what}: no binary floating point type"
            );
        }
    }

    /// The embedded dictionaries, loaded.
    fn embedded_dictionaries() -> [(&'static Dictionary, &'static str); 4] {
        [
            (embedded(Dictionary::fix42(), "FIX 4.2"), "FIX 4.2"),
            (embedded(Dictionary::fix44(), "FIX 4.4"), "FIX 4.4"),
            (embedded(Dictionary::fixt11(), "FIXT 1.1"), "FIXT 1.1"),
            (
                embedded(Dictionary::fix50sp2(), "FIX 5.0 SP2"),
                "FIX 5.0 SP2",
            ),
        ]
    }

    /// The names of the types declared in `code`, generic parameters
    /// dropped (`XView<'m, 'a>` is `XView`).
    fn declared_types(code: &str) -> Vec<&str> {
        code.lines()
            .filter_map(|text| text.trim_start().strip_prefix("pub struct "))
            .filter_map(|rest| rest.split([' ', '<']).next())
            .collect()
    }

    #[test]
    fn test_generate_entry_structs_pair_with_the_group_views() {
        // ADR-0019: absent a name collision, the entry struct of a group is
        // its view's base followed by `Entry` (`PartiesNoPartyIDsEntry` and
        // `PartiesNoPartyIDsView`). None of the embedded dictionaries has a
        // collision, so the two sets of bases are equal.
        let generator = CodeGenerator::new();
        for (dict, what) in embedded_dictionaries() {
            let code = generate(&generator, dict);
            let views = match generator.generate_views(dict) {
                Ok(views) => views,
                Err(err) => panic!("{what} views must generate: {err}"),
            };
            let entries: std::collections::BTreeSet<&str> = declared_types(&code)
                .into_iter()
                .filter_map(|name| name.strip_suffix("Entry"))
                .collect();
            let messages: HashSet<&str> = declared_types(messages_module(&code))
                .into_iter()
                .filter(|name| !name.ends_with("Entry"))
                .collect();
            assert_eq!(messages.len(), dict.messages().count(), "{what}");
            let group_views: std::collections::BTreeSet<&str> = declared_types(&views)
                .into_iter()
                .filter_map(|name| name.strip_suffix("View"))
                .filter(|base| !messages.contains(base))
                .collect();
            assert_eq!(entries, group_views, "{what}");
            // Every embedded dictionary has groups in message bodies (FIXT
            // 1.1 in the Logon and XMLnonFIX).
            assert!(!entries.is_empty(), "{what}");
        }
    }

    /// Collects the field tags one level reaches, its own and its
    /// components' (recursively), without entering groups; the groups met
    /// are pushed to `groups`, each a level of its own.
    fn level_tags<'d>(
        dict: &'d Dictionary,
        members: Vec<ironfix_dictionary::schema::MemberRef<'d>>,
        tags: &mut Vec<u32>,
        groups: &mut Vec<&'d GroupDef>,
    ) {
        use ironfix_dictionary::schema::MemberRef;
        for member in members {
            match member {
                MemberRef::Field(field) => tags.push(field.tag),
                MemberRef::Group(group) => groups.push(group),
                MemberRef::Component(reference) => {
                    if let Some(component) = dict.get_component(&reference.name) {
                        level_tags(dict, component.members().collect(), tags, groups);
                    }
                }
            }
        }
    }

    #[test]
    fn test_embedded_dictionaries_reach_no_tag_twice_at_one_level() {
        // ADR-0019's "not covered" case, a tag a message (or an entry) lists
        // and also reaches through one of its components, becomes a field of
        // each struct. No message body and no group entry of the embedded
        // dictionaries reaches a tag twice, so none of their outputs has it.
        for (dict, what) in embedded_dictionaries() {
            let mut levels: Vec<(String, Vec<ironfix_dictionary::schema::MemberRef<'_>>)> = dict
                .messages()
                .map(|message| {
                    (
                        format!("message {}", message.name),
                        message.members().collect(),
                    )
                })
                .collect();
            let mut checked = 0usize;
            while let Some((scope, members)) = levels.pop() {
                let mut tags = Vec::new();
                let mut groups = Vec::new();
                level_tags(dict, members, &mut tags, &mut groups);
                let unique: HashSet<u32> = tags.iter().copied().collect();
                assert_eq!(
                    unique.len(),
                    tags.len(),
                    "{what}: {scope} reaches a tag twice"
                );
                for group in groups {
                    levels.push((
                        format!("group {} of {scope}", group.name),
                        group.members().collect(),
                    ));
                }
                checked += 1;
            }
            assert!(checked >= dict.messages().count(), "{what}");
        }
    }

    #[test]
    fn test_generate_respects_configured_visibility() {
        let generator = CodeGenerator::with_config(GeneratorConfig {
            visibility: "pub(crate)".to_string(),
            ..GeneratorConfig::default()
        });
        let code = generate(&generator, fix44());
        assert!(code.contains("pub(crate) mod fields {"));
        assert!(code.contains("pub(crate) mod messages {"));
        assert!(code.contains("pub(crate) mod components {"));
        assert!(code.contains("pub(crate) type FixDecimal"));
    }

    /// Returns the text of the generated `messages` module.
    #[track_caller]
    fn messages_module(code: &str) -> &str {
        let Some(start) = code.find("mod messages {") else {
            panic!("the messages module must be generated");
        };
        let end = code.find("mod components {").unwrap_or(code.len());
        match code.get(start..end) {
            Some(module) => module,
            None => panic!("the messages module must be sliceable"),
        }
    }

    /// Returns the text of the generated `components` module.
    #[track_caller]
    fn components_module(code: &str) -> &str {
        let Some(start) = code.find("mod components {") else {
            panic!("the components module must be generated");
        };
        match code.get(start..) {
            Some(module) => module,
            None => panic!("the components module must be sliceable"),
        }
    }

    /// Loads an embedded dictionary, failing the test with the load error.
    #[track_caller]
    fn embedded(
        loaded: Result<&'static Dictionary, ironfix_dictionary::DictionaryError>,
        what: &str,
    ) -> &'static Dictionary {
        match loaded {
            Ok(dict) => dict,
            Err(err) => panic!("the embedded {what} dictionary must load: {err}"),
        }
    }

    /// Returns the body of the generated struct `name`.
    #[track_caller]
    fn struct_body<'c>(code: &'c str, name: &str) -> &'c str {
        let header = format!("pub struct {name} {{");
        let Some(start) = code.find(&header) else {
            panic!("{name} must be generated");
        };
        let Some(len) = code.get(start..).and_then(|rest| rest.find("\n    }")) else {
            panic!("{name} struct must be terminated");
        };
        match code.get(start..start + len) {
            Some(body) => body,
            None => panic!("{name} struct body must be sliceable"),
        }
    }

    #[test]
    fn test_generate_fix44_emits_the_self_closing_xml_non_fix_message() {
        // FIX44.xml defines `<message name='XMLnonFIX' msgtype='n' ... />`;
        // the loader keeps it, so it is generated as a field-less struct.
        let code = generate(&CodeGenerator::new(), fix44());
        assert!(code.contains("/// XMLnonFIX message (MsgType=n)."));
        assert!(code.contains("pub struct XMLnonFIX {}"));
    }

    #[test]
    fn test_generate_embedded_fix42_succeeds_with_decimal_prices() {
        let code = generate(
            &CodeGenerator::new(),
            embedded(Dictionary::fix42(), "FIX 4.2"),
        );
        assert!(code.starts_with("// Generated FIX.4.2 definitions."));
        assert!(code.contains("pub type FixDecimal = ::rust_decimal::Decimal;"));
        let body = struct_body(&code, "NewOrderSingle");
        // HandlInst(21) is required in FIX 4.2 NewOrderSingle.
        assert!(body.contains("pub handl_inst: char,"), "{body}");
        assert!(
            body.contains("pub price: ::core::option::Option<FixDecimal>,"),
            "{body}"
        );
        assert!(
            body.contains("pub order_qty: ::core::option::Option<FixDecimal>,"),
            "{body}"
        );
        // FIX 4.2 defines no component, so there is no components module.
        assert!(!code.contains("mod components"));
        assert!(!code.contains("f64"));
        assert!(!code.contains("f32"));
    }

    #[test]
    fn test_generate_embedded_fixt11_succeeds_without_a_decimal_alias() {
        let code = generate(
            &CodeGenerator::new(),
            embedded(Dictionary::fixt11(), "FIXT 1.1"),
        );
        assert!(code.starts_with("// Generated FIXT.1.1 definitions."));
        // No FIXT 1.1 field is a price, quantity, or amount.
        assert!(!code.contains("FixDecimal"));
        let logon = struct_body(&code, "Logon");
        assert!(
            logon.contains("pub default_appl_ver_id: ::std::string::String,"),
            "{logon}"
        );
        assert!(logon.contains("pub heart_bt_int: i64,"), "{logon}");
        // The embedded FIXT 1.1 dictionary defines the Logon NoMsgTypes(384)
        // group.
        assert!(logon.contains("pub no_msg_types:"), "{logon}");
        assert!(code.contains("pub struct LogonNoMsgTypesEntry {"));
        assert!(!code.contains("f64"));
    }

    #[test]
    fn test_generate_embedded_fix50sp2_succeeds_with_decimal_prices() {
        // The output is compiled in full by ironfix-codegen-check.
        let code = generate(
            &CodeGenerator::new(),
            embedded(Dictionary::fix50sp2(), "FIX 5.0 SP2"),
        );
        assert!(code.starts_with("// Generated FIX.5.0SP2 definitions."));
        assert!(code.contains("pub type FixDecimal = ::rust_decimal::Decimal;"));
        let body = struct_body(&code, "NewOrderSingle");
        assert!(
            body.contains("pub cl_ord_id: ::std::string::String,"),
            "{body}"
        );
        assert!(
            body.contains("pub price: ::core::option::Option<FixDecimal>,"),
            "{body}"
        );
        assert!(
            body.contains("pub instrument: super::components::Instrument,"),
            "{body}"
        );
        // One struct per component, however many messages list it.
        assert_eq!(code.matches("pub struct Instrument {").count(), 1);
        // Orchestra holds Parties as a group: one entry type per message.
        assert_eq!(
            code.matches("pub struct NewOrderSingleNoPartyIDsEntry {")
                .count(),
            1
        );
        // XID-typed fields (FIX 5.0 SP2 only) are emitted as String.
        assert!(
            code.contains(
                "pub cash_settl_term_xid: ::core::option::Option<::std::string::String>,"
            )
        );
        assert!(!code.contains("f64"));
        assert!(!code.contains("f32"));
    }

    #[test]
    fn test_generate_without_messages_emits_no_decimal_alias() {
        let generator = CodeGenerator::with_config(GeneratorConfig {
            generate_messages: false,
            ..GeneratorConfig::default()
        });
        let code = generate(&generator, fix44());
        assert!(!code.contains("FixDecimal"));
        assert!(code.contains("pub mod fields {"));
    }

    /// Builds a dictionary with one message referencing `component`.
    fn dict_with_component(component: ComponentDef) -> Dictionary {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(11, "ClOrdID", FieldType::String));
        dict.add_component(component);
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![
                SchemaMember::Field(SchemaFieldRef {
                    tag: 11,
                    name: "ClOrdID".to_string(),
                    required: true,
                }),
                SchemaMember::Component(ComponentRef::new("Looper", false)),
            ],
        ));
        dict
    }

    #[test]
    fn test_generate_self_referencing_component_is_a_typed_error() {
        let dict = dict_with_component(ComponentDef::new(
            "Looper",
            vec![SchemaMember::Component(ComponentRef::new("Looper", false))],
        ));
        assert_eq!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::ComponentCycle {
                name: "Looper".to_string(),
                path: "Looper -> Looper".to_string(),
            })
        );
    }

    #[test]
    fn test_generate_unknown_component_is_a_typed_error() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(11, "ClOrdID", FieldType::String));
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![SchemaMember::Component(ComponentRef::new("Nowhere", false))],
        ));
        assert_eq!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::UnknownComponent {
                name: "Nowhere".to_string(),
                scope: "message NewOrderSingle".to_string(),
            })
        );
    }

    #[test]
    fn test_generate_unknown_field_tag_is_a_typed_error() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![SchemaMember::Field(SchemaFieldRef {
                tag: 9999,
                name: "Mystery".to_string(),
                required: true,
            })],
        ));
        assert_eq!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::UnknownField {
                tag: 9999,
                scope: "message NewOrderSingle".to_string(),
            })
        );
    }

    /// A field reference.
    fn field(tag: u32, name: &str, required: bool) -> SchemaMember {
        SchemaMember::Field(SchemaFieldRef {
            tag,
            name: name.to_string(),
            required,
        })
    }

    /// A component reference.
    fn component(name: &str, required: bool) -> SchemaMember {
        SchemaMember::Component(ComponentRef::new(name, required))
    }

    #[test]
    fn test_generate_component_requiredness_belongs_to_each_reference() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(11, "ClOrdID", FieldType::String));
        dict.add_field(FieldDef::new(55, "Symbol", FieldType::String));
        dict.add_component(ComponentDef::new(
            "Instrument",
            vec![field(55, "Symbol", true)],
        ));
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![component("Instrument", false)],
        ));
        dict.add_message(MessageDef::new(
            "F",
            "OrderCancelRequest",
            MessageCategory::App,
            vec![field(11, "ClOrdID", true), component("Instrument", true)],
        ));
        let code = generate(&CodeGenerator::new(), &dict);
        // One type, required where the component is present at all.
        assert_eq!(code.matches("pub struct Instrument {").count(), 1);
        let instrument = struct_body(&code, "Instrument");
        assert!(
            instrument.contains("pub symbol: ::std::string::String,"),
            "{instrument}"
        );
        // Each reference decides whether the component is optional.
        let order = struct_body(&code, "NewOrderSingle");
        assert!(
            order
                .contains("pub instrument: ::core::option::Option<super::components::Instrument>,"),
            "{order}"
        );
        let cancel = struct_body(&code, "OrderCancelRequest");
        assert!(
            cancel.contains("pub instrument: super::components::Instrument,"),
            "{cancel}"
        );
    }

    #[test]
    fn test_generate_component_reached_only_through_a_group_entry_is_generated() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(78, "NoAllocs", FieldType::NumInGroup));
        dict.add_field(FieldDef::new(79, "AllocAccount", FieldType::String));
        dict.add_field(FieldDef::new(80, "AllocQty", FieldType::Qty));
        dict.add_component(ComponentDef::new(
            "AllocQtyData",
            vec![field(80, "AllocQty", false)],
        ));
        // Never listed by a message: not generated.
        dict.add_component(ComponentDef::new(
            "Unused",
            vec![field(80, "AllocQty", false)],
        ));
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![SchemaMember::Group(GroupDef::new(
                78,
                "NoAllocs",
                79,
                false,
                vec![
                    field(79, "AllocAccount", true),
                    component("AllocQtyData", false),
                ],
            ))],
        ));
        let code = generate(&CodeGenerator::new(), &dict);
        // The entry lives in `messages` and names the component's module.
        let entry = struct_body(&code, "NewOrderSingleNoAllocsEntry");
        assert!(
            entry.contains(
                "pub alloc_qty_data: ::core::option::Option<super::components::AllocQtyData>,"
            ),
            "{entry}"
        );
        let qty = struct_body(&code, "AllocQtyData");
        assert!(
            qty.contains("pub alloc_qty: ::core::option::Option<FixDecimal>,"),
            "{qty}"
        );
        assert!(!code.contains("Unused"), "{code}");
        assert!(components_module(&code).contains("    use super::FixDecimal;"));
        assert!(!messages_module(&code).contains("use super::FixDecimal;"));
    }

    #[test]
    fn test_generate_component_inside_a_component_is_referenced_by_its_bare_name() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(55, "Symbol", FieldType::String));
        dict.add_field(FieldDef::new(454, "NoSecurityAltID", FieldType::NumInGroup));
        dict.add_field(FieldDef::new(455, "SecurityAltID", FieldType::String));
        dict.add_component(ComponentDef::new(
            "SecAltIDGrp",
            vec![SchemaMember::Group(GroupDef::new(
                454,
                "NoSecurityAltID",
                455,
                false,
                vec![field(455, "SecurityAltID", true)],
            ))],
        ));
        dict.add_component(ComponentDef::new(
            "Instrument",
            vec![field(55, "Symbol", true), component("SecAltIDGrp", false)],
        ));
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![component("Instrument", true)],
        ));
        let code = generate(&CodeGenerator::new(), &dict);
        let instrument = struct_body(&code, "Instrument");
        assert!(
            instrument.contains("pub sec_alt_idgrp: ::core::option::Option<SecAltIDGrp>,"),
            "{instrument}"
        );
        let group = struct_body(&code, "SecAltIDGrp");
        assert!(
            group.contains(
                "::core::option::Option<::std::vec::Vec<SecAltIDGrpNoSecurityAltIDEntry>>,"
            ),
            "{group}"
        );
        // Components ordered by name, each followed by its entries.
        let names = struct_names(components_module(&code));
        assert_eq!(
            names,
            [
                "Instrument",
                "SecAltIDGrp",
                "SecAltIDGrpNoSecurityAltIDEntry"
            ]
        );
    }

    #[test]
    fn test_generate_cycle_through_two_components_is_a_typed_error() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_component(ComponentDef::new("A", vec![component("B", false)]));
        dict.add_component(ComponentDef::new("B", vec![component("A", false)]));
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![component("A", false)],
        ));
        assert_eq!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::ComponentCycle {
                name: "A".to_string(),
                path: "A -> B -> A".to_string(),
            })
        );
    }

    #[test]
    fn test_generate_unknown_component_inside_a_component_group_names_its_scope() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(453, "NoPartyIDs", FieldType::NumInGroup));
        dict.add_field(FieldDef::new(448, "PartyID", FieldType::String));
        dict.add_component(ComponentDef::new(
            "Parties",
            vec![SchemaMember::Group(GroupDef::new(
                453,
                "NoPartyIDs",
                448,
                false,
                vec![field(448, "PartyID", true), component("Nowhere", false)],
            ))],
        ));
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![component("Parties", false)],
        ));
        assert_eq!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::UnknownComponent {
                name: "Nowhere".to_string(),
                scope: "group NoPartyIDs of component Parties".to_string(),
            })
        );
    }

    #[test]
    fn test_generate_unknown_field_inside_a_component_names_the_component() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_component(ComponentDef::new(
            "Instrument",
            vec![field(9999, "Mystery", false)],
        ));
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![component("Instrument", false)],
        ));
        assert_eq!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::UnknownField {
                tag: 9999,
                scope: "component Instrument".to_string(),
            })
        );
    }

    #[test]
    fn test_generate_component_name_with_a_hyphen_is_a_typed_error() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_component(ComponentDef::new("Bad-Name", Vec::new()));
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![component("Bad-Name", false)],
        ));
        assert_eq!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::UnnameableItem {
                what: "component",
                name: "Bad-Name".to_string(),
            })
        );
    }

    #[test]
    fn test_generate_no_type_takes_the_decimal_alias_name() {
        // A message and a component named like the alias would clash with
        // `use super::FixDecimal;`; they take a suffix instead.
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(44, "Price", FieldType::Price));
        dict.add_component(ComponentDef::new(
            "FixDecimal",
            vec![field(44, "Price", false)],
        ));
        dict.add_message(MessageDef::new(
            "U1",
            "FixDecimal",
            MessageCategory::App,
            vec![field(44, "Price", false), component("FixDecimal", false)],
        ));
        let code = generate(&CodeGenerator::new(), &dict);
        assert_eq!(struct_names(messages_module(&code)), ["FixDecimal2"]);
        assert_eq!(struct_names(components_module(&code)), ["FixDecimal2"]);
        assert!(
            code.contains(
                "pub fix_decimal: ::core::option::Option<super::components::FixDecimal2>,"
            )
        );
    }

    #[test]
    fn test_generate_keeps_both_a_count_field_and_the_group_sharing_its_tag() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(453, "NoPartyIDs", FieldType::NumInGroup));
        dict.add_field(FieldDef::new(448, "PartyID", FieldType::String));
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            // A dictionary that lists the count field directly as well as the
            // group it counts. Dropping either would lose information.
            vec![
                SchemaMember::Field(SchemaFieldRef {
                    tag: 453,
                    name: "NoPartyIDs".to_string(),
                    required: false,
                }),
                SchemaMember::Group(GroupDef::new(
                    453,
                    "NoPartyIDs",
                    448,
                    false,
                    vec![SchemaMember::Field(SchemaFieldRef {
                        tag: 448,
                        name: "PartyID".to_string(),
                        required: true,
                    })],
                )),
            ],
        ));
        let code = generate(&CodeGenerator::new(), &dict);
        assert!(
            code.contains("pub no_party_ids: ::core::option::Option<i64>,"),
            "{code}"
        );
        assert!(
            code.contains("pub no_party_ids_453: ::core::option::Option<::std::vec::Vec<NewOrderSingleNoPartyIDsEntry>>,"),
            "{code}"
        );
    }

    #[test]
    fn test_generate_member_listed_twice_in_one_definition_appears_once() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(55, "Symbol", FieldType::String));
        dict.add_field(FieldDef::new(54, "Side", FieldType::Char));
        dict.add_component(ComponentDef::new(
            "Instrument",
            vec![field(55, "Symbol", false)],
        ));
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![
                field(55, "Symbol", true),
                field(55, "Symbol", false),
                component("Instrument", false),
                component("Instrument", true),
                field(54, "Side", true),
            ],
        ));
        let code = generate(&CodeGenerator::new(), &dict);
        let order = struct_body(&code, "NewOrderSingle");
        // The first listing wins, with its requiredness.
        assert_eq!(order.matches("pub symbol:").count(), 1, "{order}");
        assert!(
            order.contains("pub symbol: ::std::string::String,"),
            "{order}"
        );
        assert_eq!(order.matches("pub instrument:").count(), 1, "{order}");
        assert!(
            order
                .contains("pub instrument: ::core::option::Option<super::components::Instrument>,"),
            "{order}"
        );
        // The same tag inside the component stays a field of the component.
        let instrument = struct_body(&code, "Instrument");
        assert!(
            instrument.contains("pub symbol: ::core::option::Option<::std::string::String>,"),
            "{instrument}"
        );
    }

    #[test]
    fn test_generate_cycle_closing_through_a_group_is_a_typed_error() {
        // A hand-built dictionary where component `Parties` contains a group
        // whose entry references `Parties` again: component -> group ->
        // component. The cycle closes across the group boundary, which reset a
        // fresh guard at every group and recursed forever.
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(453, "NoPartyIDs", FieldType::NumInGroup));
        dict.add_field(FieldDef::new(448, "PartyID", FieldType::String));
        dict.add_component(ComponentDef::new(
            "Parties",
            vec![SchemaMember::Group(GroupDef::new(
                453,
                "NoPartyIDs",
                448,
                false,
                vec![
                    SchemaMember::Field(SchemaFieldRef {
                        tag: 448,
                        name: "PartyID".to_string(),
                        required: true,
                    }),
                    SchemaMember::Component(ComponentRef::new("Parties", false)),
                ],
            ))],
        ));
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![SchemaMember::Component(ComponentRef::new("Parties", false))],
        ));
        assert_eq!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::ComponentCycle {
                name: "Parties".to_string(),
                path: "Parties -> Parties".to_string(),
            })
        );
    }

    #[test]
    fn test_generate_acyclic_chain_past_the_ceiling_is_a_typed_error() {
        // A chain of distinct components, each referencing the next, deeper than
        // the ceiling: never a cycle (no name repeats), so only the depth guard
        // stops it before the recursion overflows the stack.
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(11, "ClOrdID", FieldType::String));
        let length = MAX_NESTING_DEPTH + 10;
        for index in 0..length {
            let next = if index + 1 < length {
                vec![ComponentRef::new(format!("Comp{}", index + 1), false)]
            } else {
                Vec::new()
            };
            dict.add_component(ComponentDef::new(
                format!("Comp{index}"),
                next.into_iter().map(SchemaMember::Component),
            ));
        }
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![
                SchemaMember::Field(SchemaFieldRef {
                    tag: 11,
                    name: "ClOrdID".to_string(),
                    required: true,
                }),
                SchemaMember::Component(ComponentRef::new("Comp0", false)),
            ],
        ));
        assert!(matches!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::MaxDepthExceeded {
                limit: MAX_NESTING_DEPTH,
                ..
            })
        ));
    }

    #[test]
    fn test_is_valid_ident_rejects_punctuation_and_leading_digits() {
        assert!(is_valid_ident("cl_ord_id"));
        assert!(is_valid_ident("_private"));
        assert!(is_valid_ident("Symbol55"));
        // A converted name that still carries a hyphen, space, or dot, or that
        // is empty or digit-leading, is not a legal identifier.
        assert!(!is_valid_ident("foo-bar"));
        assert!(!is_valid_ident("bad name"));
        assert!(!is_valid_ident("a.b"));
        assert!(!is_valid_ident(""));
        assert!(!is_valid_ident("1foo"));
    }

    #[test]
    fn test_generate_field_ref_name_with_a_hyphen_is_a_typed_error() {
        // A dictionary is external input; a field name that snake-cases to an
        // invalid identifier must be a typed error, not `Ok` with output that
        // will not compile.
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(11, "Foo-Bar", FieldType::String));
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![SchemaMember::Field(SchemaFieldRef {
                tag: 11,
                name: "Foo-Bar".to_string(),
                required: true,
            })],
        ));
        assert_eq!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::UnnameableItem {
                what: "field",
                name: "Foo-Bar".to_string(),
            })
        );
    }

    #[test]
    fn test_generate_field_constant_name_with_a_space_is_a_typed_error() {
        // The `fields` module path: a field the constants module reaches, even
        // when no message references it, is validated the same way.
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(11, "Bad Name", FieldType::String));
        assert_eq!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::UnnameableItem {
                what: "field",
                name: "Bad Name".to_string(),
            })
        );
    }

    #[test]
    fn test_generate_message_name_with_a_hyphen_is_a_typed_error() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_message(MessageDef::new(
            "D",
            "New-Order",
            MessageCategory::App,
            Vec::new(),
        ));
        assert_eq!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::UnnameableItem {
                what: "message",
                name: "New-Order".to_string(),
            })
        );
    }

    #[test]
    fn test_generate_group_name_with_a_hyphen_is_a_typed_error() {
        // A punctuated group name would break the generated entry struct's
        // type name; it is rejected before the struct is emitted.
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(453, "NoParties", FieldType::NumInGroup));
        dict.add_field(FieldDef::new(448, "PartyID", FieldType::String));
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            vec![SchemaMember::Group(GroupDef::new(
                453,
                "No-Parties",
                448,
                false,
                vec![SchemaMember::Field(SchemaFieldRef {
                    tag: 448,
                    name: "PartyID".to_string(),
                    required: true,
                })],
            ))],
        ));
        assert_eq!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::UnnameableItem {
                what: "group",
                name: "No-Parties".to_string(),
            })
        );
    }
}
