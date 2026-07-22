/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Code generator for FIX dictionaries.
//!
//! Generates Rust source code from a loaded [`Dictionary`]: one `u32` constant
//! per field tag, and one struct per message.
//!
//! # What the generated code contains
//!
//! ```text
//! // Generated FIX.4.4 definitions.
//!
//! pub type FixDecimal = rust_decimal::Decimal;
//!
//! /// Field tag constants.
//! pub mod fields {
//!     /// ClOrdID (tag 11).
//!     pub const CL_ORD_ID: u32 = 11;
//! }
//!
//! /// Message type definitions.
//! pub mod messages {
//!     use super::FixDecimal;
//!
//!     /// NewOrderSingle message (MsgType=D).
//!     #[derive(Debug, Clone)]
//!     pub struct NewOrderSingle {
//!         /// ClOrdID (tag 11).
//!         pub cl_ord_id: String,
//!         /// Price (tag 44).
//!         pub price: Option<FixDecimal>,
//!         /// NoPartyIDs (tag 453) repeating group.
//!         pub no_party_ids: Option<Vec<NewOrderSingleNoPartyIDsEntry>>,
//!     }
//! }
//! ```
//!
//! The file header is written with `//` line comments rather than `//!`, so the
//! output can be `include!`d inside a module — the usual `build.rs` + `OUT_DIR`
//! workflow, where an inner attribute would be rejected.
//!
//! # What it does not contain
//!
//! The generated structs are **data definitions only**: no `FixMessage`
//! implementations, no encode/decode. Deriving those is `ironfix-derive`'s job,
//! and the two are not
//! wired together — nothing in this workspace consumes either.
//!
//! # Fidelity limits, stated rather than hidden
//!
//! - **Field order is not wire order.** A struct lists its direct fields, then
//!   the fields contributed by its components, then its repeating groups. The
//!   QuickFIX XML interleaving is not retained by the loader, so it cannot be
//!   reproduced here.
//! - **Component-contributed fields are always optional.** A `MessageDef`
//!   records the *names* of the components it uses, not whether each is
//!   required, so a field that is required inside a component is emitted as
//!   `Option<T>` — the representable choice that cannot be wrong.
//! - **Group entries are flattened the same way** and are validated by nothing
//!   here; conformance checking is `ironfix_dictionary::Validator`.

use ironfix_dictionary::schema::{
    ComponentRef, Dictionary, FieldDef, FieldType, GroupDef, MessageDef,
};
// `FieldRef` also names a zero-copy wire field in `ironfix-core`; this is the
// schema-side one (tag, name, required).
use ironfix_dictionary::schema::FieldRef as SchemaFieldRef;
use std::collections::HashSet;
use thiserror::Error;

/// Name of the generated alias for the decimal type.
///
/// Emitted once per file as `pub type FixDecimal = rust_decimal::Decimal;`, so
/// every FIX `Price` / `Qty` / `Amt` / `Percentage` field resolves to
/// [`rust_decimal::Decimal`] through a single declaration — and never to
/// `f64`.
const DECIMAL_ALIAS: &str = "FixDecimal";

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
const MAX_NESTING_DEPTH: usize = 32;

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

    /// A component contains itself, directly or through other components.
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

    /// Components and groups nested deeper than [`MAX_NESTING_DEPTH`] without
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
}

/// Configuration for code generation.
#[derive(Debug, Clone)]
pub struct GeneratorConfig {
    /// Whether to generate the `fields` module of tag constants.
    pub generate_fields: bool,
    /// Whether to generate the `messages` module of message structs.
    pub generate_messages: bool,
    /// Whether message structs include the fields contributed by components
    /// and the repeating groups they contain.
    ///
    /// With this off, a generated struct carries only the fields listed
    /// directly on the message — for FIX 4.4 that leaves `NewOrderSingle`
    /// without `Symbol` (55), which lives in the `Instrument` component. It is
    /// on by default.
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
    /// # Arguments
    /// * `dict` - The FIX dictionary to generate code from
    ///
    /// # Errors
    /// Returns [`GeneratorError`] if the dictionary references a field or
    /// component it does not define, or if a component contains itself. The
    /// generator never drops such an item silently.
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

        let models = if self.config.generate_messages {
            self.build_messages(dict)?
        } else {
            Vec::new()
        };
        let uses_decimal = models
            .iter()
            .any(|model| model.fields.iter().any(|field| field.uses_decimal));

        if uses_decimal {
            line(
                &mut code,
                "/// Decimal type for FIX price, quantity, and amount fields.",
            );
            line(
                &mut code,
                &format!(
                    "{} type {DECIMAL_ALIAS} = rust_decimal::Decimal;",
                    self.config.visibility
                ),
            );
            line(&mut code, "");
        }

        if self.config.generate_fields {
            self.emit_fields_module(&mut code, dict)?;
        }

        if self.config.generate_messages {
            self.emit_messages_module(&mut code, &models, uses_decimal);
        }

        Ok(code)
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

    /// Emits the `messages` module from already-built models.
    fn emit_messages_module(&self, code: &mut String, models: &[StructModel], uses_decimal: bool) {
        line(code, "/// Message type definitions.");
        line(code, &format!("{} mod messages {{", self.config.visibility));
        if uses_decimal {
            line(code, &format!("    use super::{DECIMAL_ALIAS};"));
            line(code, "");
        }

        for model in models {
            line(code, &format!("    /// {}", model.doc));
            line(code, "    #[derive(Debug, Clone)]");
            if model.fields.is_empty() {
                line(code, &format!("    pub struct {} {{}}", model.name));
                line(code, "");
                continue;
            }
            line(code, &format!("    pub struct {} {{", model.name));
            for field in &model.fields {
                line(code, &format!("        /// {}", field.doc));
                line(code, &format!("        pub {}: {},", field.name, field.ty));
            }
            line(code, "    }");
            line(code, "");
        }

        line(code, "}");
    }

    /// Builds a model per message, plus one per repeating-group entry.
    ///
    /// Messages are ordered by MsgType so the output is deterministic even
    /// though the dictionary stores them in a `HashMap`.
    fn build_messages(&self, dict: &Dictionary) -> Result<Vec<StructModel>, GeneratorError> {
        let mut messages: Vec<&MessageDef> = dict.messages().collect();
        messages.sort_by(|a, b| a.msg_type.cmp(&b.msg_type));

        let mut type_names: HashSet<String> = HashSet::with_capacity(messages.len());
        let mut models: Vec<StructModel> = Vec::with_capacity(messages.len());

        for message in messages {
            let scope = format!("message {}", message.name);
            let base = to_pascal_case(&message.name);
            if !is_valid_ident(&base) {
                return Err(GeneratorError::UnnameableItem {
                    what: "message",
                    name: message.name.clone(),
                });
            }
            let name = unique_type_name(&mut type_names, &to_type_ident(&base));

            let mut stack: Vec<String> = Vec::new();
            let mut members: Vec<Member<'_>> = Vec::new();
            self.collect(
                dict,
                &scope,
                &message.fields,
                &message.groups,
                &message.components,
                false,
                0,
                &mut stack,
                &mut members,
            )?;

            let doc = format!("{} message (MsgType={}).", message.name, message.msg_type);
            let model = self.build_struct(
                dict,
                &scope,
                name,
                doc,
                &members,
                0,
                &mut type_names,
                &mut models,
            )?;
            models.push(model);
        }

        Ok(models)
    }

    /// Collects the fields and groups a scope contributes, expanding
    /// components when [`GeneratorConfig::generate_components`] is set.
    ///
    /// `from_component` marks members reached through a component reference:
    /// the dictionary does not record whether such a reference is required, so
    /// they are emitted as optional.
    ///
    /// `depth` is the current component-and-group nesting; it grows across every
    /// recursive descent (a component here, a group entry in [`build_struct`])
    /// and is checked against [`MAX_NESTING_DEPTH`] so a deep but acyclic
    /// dictionary cannot overflow the stack.
    ///
    /// `stack` is the chain of component names reached so far, threaded so a
    /// cycle that closes across a group boundary is still caught: each deferred
    /// [`Member::Group`] captures it, and [`build_struct`] seeds the group
    /// body's own `collect` with it rather than starting fresh.
    #[allow(clippy::too_many_arguments)]
    fn collect<'d>(
        &self,
        dict: &'d Dictionary,
        scope: &str,
        fields: &'d [SchemaFieldRef],
        groups: &'d [GroupDef],
        components: &'d [ComponentRef],
        from_component: bool,
        depth: usize,
        stack: &mut Vec<String>,
        out: &mut Vec<Member<'d>>,
    ) -> Result<(), GeneratorError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(GeneratorError::MaxDepthExceeded {
                scope: scope.to_string(),
                limit: MAX_NESTING_DEPTH,
            });
        }

        for field in fields {
            out.push(Member::Field {
                field,
                required: field.required && !from_component,
            });
        }

        if self.config.generate_components {
            for component_ref in components {
                let name = &component_ref.name;
                if stack.iter().any(|visited| visited == name) {
                    let mut path = stack.clone();
                    path.push(name.clone());
                    return Err(GeneratorError::ComponentCycle {
                        name: name.clone(),
                        path: path.join(" -> "),
                    });
                }
                let component =
                    dict.get_component(name)
                        .ok_or_else(|| GeneratorError::UnknownComponent {
                            name: name.clone(),
                            scope: scope.to_string(),
                        })?;
                stack.push(name.clone());
                let nested_scope = format!("component {name}");
                self.collect(
                    dict,
                    &nested_scope,
                    &component.fields,
                    &component.groups,
                    &component.components,
                    true,
                    depth + 1,
                    stack,
                    out,
                )?;
                stack.pop();
            }
        }

        for group in groups {
            out.push(Member::Group {
                def: group,
                required: group.required && !from_component,
                ancestry: stack.clone(),
            });
        }

        Ok(())
    }

    /// Turns collected members into a struct model, emitting one entry struct
    /// per repeating group into `models`.
    ///
    /// `depth` is the current nesting; it is checked against
    /// [`MAX_NESTING_DEPTH`] and grows by one on descent into each group entry,
    /// so a deep chain of nested groups cannot overflow the stack.
    #[allow(clippy::too_many_arguments)]
    fn build_struct(
        &self,
        dict: &Dictionary,
        scope: &str,
        name: String,
        doc: String,
        members: &[Member<'_>],
        depth: usize,
        type_names: &mut HashSet<String>,
        models: &mut Vec<StructModel>,
    ) -> Result<StructModel, GeneratorError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(GeneratorError::MaxDepthExceeded {
                scope: scope.to_string(),
                limit: MAX_NESTING_DEPTH,
            });
        }

        let mut fields: Vec<StructFieldModel> = Vec::with_capacity(members.len());
        // Field tags and group count tags are tracked apart: a dictionary that
        // lists a count field directly *and* as a group keeps both, one as the
        // count and one as the entries, rather than losing the group.
        let mut seen_field_tags: HashSet<u32> = HashSet::with_capacity(members.len());
        let mut seen_group_tags: HashSet<u32> = HashSet::new();
        let mut used_names: HashSet<String> = HashSet::with_capacity(members.len());

        for member in members {
            match member {
                Member::Field { field, required } => {
                    if !seen_field_tags.insert(field.tag) {
                        // The same field reached twice through two components
                        // is one struct field, not two.
                        continue;
                    }
                    let def =
                        dict.get_field(field.tag)
                            .ok_or_else(|| GeneratorError::UnknownField {
                                tag: field.tag,
                                scope: scope.to_string(),
                            })?;
                    let ident = resolve_field_name(&mut used_names, &field.name, field.tag)?;
                    let base = field_type_to_rust(def.field_type);
                    fields.push(StructFieldModel {
                        doc: field_doc(def),
                        name: ident,
                        ty: wrap_optional(base, *required),
                        uses_decimal: base == DECIMAL_ALIAS,
                    });
                }
                Member::Group {
                    def,
                    required,
                    ancestry,
                } => {
                    if !seen_group_tags.insert(def.count_tag) {
                        // The same group reached twice through two components.
                        continue;
                    }
                    let entry_base = format!("{}{}Entry", name, to_pascal_case(&def.name));
                    // `name` is already a valid identifier, so a punctuated
                    // group name is what would break `entry_base`; reject it
                    // rather than emit a struct whose name will not compile.
                    if !is_valid_ident(&entry_base) {
                        return Err(GeneratorError::UnnameableItem {
                            what: "group",
                            name: def.name.clone(),
                        });
                    }
                    let entry_name = unique_type_name(type_names, &to_type_ident(&entry_base));

                    let group_scope = format!("group {} of {scope}", def.name);
                    // Seed the group body with the component chain that reached
                    // it, not a fresh stack: a cycle that closes through this
                    // group (component A -> group -> component A) would otherwise
                    // recurse forever with the guard reset at every boundary.
                    let mut stack: Vec<String> = ancestry.clone();
                    let mut nested: Vec<Member<'_>> = Vec::new();
                    self.collect(
                        dict,
                        &group_scope,
                        &def.fields,
                        &def.groups,
                        &def.components,
                        false,
                        depth + 1,
                        &mut stack,
                        &mut nested,
                    )?;
                    let entry_doc = format!(
                        "One entry of the {} (tag {}) repeating group in {name}.",
                        def.name, def.count_tag
                    );
                    let entry = self.build_struct(
                        dict,
                        &group_scope,
                        entry_name.clone(),
                        entry_doc,
                        &nested,
                        depth + 1,
                        type_names,
                        models,
                    )?;
                    models.push(entry);

                    let ident = resolve_field_name(&mut used_names, &def.name, def.count_tag)?;
                    fields.push(StructFieldModel {
                        doc: format!(
                            "{} (tag {}) repeating group; its length is the count field.",
                            def.name, def.count_tag
                        ),
                        name: ident,
                        ty: wrap_optional(&format!("Vec<{entry_name}>"), *required),
                        uses_decimal: false,
                    });
                }
            }
        }

        Ok(StructModel { doc, name, fields })
    }
}

impl Default for CodeGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// A field or repeating group contributed to a generated struct.
#[derive(Debug)]
enum Member<'d> {
    /// A plain field reference.
    Field {
        /// The schema-side reference (tag, name, required).
        field: &'d SchemaFieldRef,
        /// Whether it is required in the scope that contributed it.
        required: bool,
    },
    /// A repeating group, generated as its own entry struct.
    Group {
        /// The group definition.
        def: &'d GroupDef,
        /// Whether the group is required in the scope that contributed it.
        required: bool,
        /// The chain of component names that reached this group, captured when
        /// the group was deferred so the guard survives the group boundary.
        ancestry: Vec<String>,
    },
}

/// A struct the generator will emit.
#[derive(Debug)]
struct StructModel {
    /// Doc comment for the struct.
    doc: String,
    /// Rust type name.
    name: String,
    /// Struct fields, in emission order.
    fields: Vec<StructFieldModel>,
}

/// A field of a generated struct.
#[derive(Debug)]
struct StructFieldModel {
    /// Doc comment for the field.
    doc: String,
    /// Rust identifier, already keyword-escaped.
    name: String,
    /// Rendered Rust type.
    ty: String,
    /// Whether the type resolves to the decimal alias.
    uses_decimal: bool,
}

/// Appends `text` and a newline to `code`.
fn line(code: &mut String, text: &str) {
    code.push_str(text);
    code.push('\n');
}

/// Wraps `ty` in `Option<...>` unless the field is required.
fn wrap_optional(ty: &str, required: bool) -> String {
    if required {
        ty.to_string()
    } else {
        format!("Option<{ty}>")
    }
}

/// Builds the doc line for a field definition.
fn field_doc(field: &FieldDef) -> String {
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
/// dropped to avoid a clash.
fn resolve_field_name(
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
    Ok(to_field_ident(&unique_name(used, &base, tag)))
}

/// Returns a name not already in `used`, disambiguating first by `tag` and
/// then by a numeric suffix.
fn unique_name(used: &mut HashSet<String>, base: &str, tag: u32) -> String {
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
fn unique_type_name(used: &mut HashSet<String>, candidate: &str) -> String {
    if used.insert(candidate.to_string()) {
        return candidate.to_string();
    }
    let mut suffix = 2usize;
    loop {
        let name = format!("{candidate}{suffix}");
        if used.insert(name.clone()) {
            return name;
        }
        suffix += 1;
    }
}

/// Returns true if `name` is a Rust keyword.
fn is_keyword(name: &str) -> bool {
    KEYWORDS.contains(&name)
}

/// Escapes a value identifier that collides with a Rust keyword.
///
/// A keyword becomes a raw identifier (`yield` -> `r#yield`); the four
/// keywords that cannot be written raw take a trailing underscore instead.
fn to_field_ident(name: &str) -> String {
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
fn to_type_ident(name: &str) -> String {
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
fn is_valid_ident(ident: &str) -> bool {
    let mut chars = ident.chars();
    let starts_valid = matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic());
    starts_valid && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Converts a string to `SCREAMING_SNAKE_CASE`.
fn to_screaming_snake_case(s: &str) -> String {
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
fn to_snake_case(s: &str) -> String {
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
fn to_pascal_case(s: &str) -> String {
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
fn field_type_to_rust(field_type: FieldType) -> &'static str {
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
        | FieldType::Reserved => "String",
        FieldType::Data | FieldType::XmlData => "Vec<u8>",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironfix_dictionary::schema::{ComponentDef, ComponentRef, MessageCategory, Version};

    /// The vendored FIX 4.4 dictionary.
    fn fix44() -> &'static Dictionary {
        match Dictionary::fix44() {
            Ok(dict) => dict,
            Err(err) => panic!("the embedded FIX 4.4 dictionary must load: {err}"),
        }
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
        assert!(code.contains("pub type FixDecimal = rust_decimal::Decimal;"));
        // Price (44) and OrderQty (38) both reach NewOrderSingle directly.
        assert!(code.contains("pub price: Option<FixDecimal>,"));
        assert!(code.contains("pub order_qty: Option<FixDecimal>,"));
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
        assert!(code.contains("pub cl_ord_id: String,"));
        // Account (1) is optional there.
        assert!(code.contains("pub account: Option<String>,"));
    }

    #[test]
    fn test_generate_fix44_new_order_single_carries_its_component_fields() {
        let code = generate(&CodeGenerator::new(), fix44());
        let Some(start) = code.find("pub struct NewOrderSingle {") else {
            panic!("NewOrderSingle must be generated");
        };
        let Some(len) = code.get(start..).and_then(|rest| rest.find("\n    }")) else {
            panic!("NewOrderSingle struct must be terminated");
        };
        let Some(body) = code.get(start..start + len) else {
            panic!("struct body must be sliceable");
        };
        // Symbol (55) lives in the Instrument component, OrderQty (38) in the
        // OrderQtyData component: without expansion the struct has neither.
        assert!(body.contains("pub symbol:"), "{body}");
        assert!(body.contains("pub order_qty:"), "{body}");
        assert!(body.contains("pub price:"), "{body}");
        // NoAllocs (78) is a repeating group on the message.
        assert!(body.contains("pub no_allocs:"), "{body}");
    }

    #[test]
    fn test_generate_fix44_emits_a_struct_per_repeating_group_entry() {
        let code = generate(&CodeGenerator::new(), fix44());
        assert!(code.contains("pub struct NewOrderSingleNoAllocsEntry {"));
        assert!(code.contains("Vec<NewOrderSingleNoAllocsEntry>"));
    }

    #[test]
    fn test_generate_without_components_omits_component_fields() {
        let generator = CodeGenerator::with_config(GeneratorConfig {
            generate_components: false,
            ..GeneratorConfig::default()
        });
        let code = generate(&generator, fix44());
        let Some(start) = code.find("pub struct NewOrderSingle {") else {
            panic!("NewOrderSingle must be generated");
        };
        let Some(len) = code.get(start..).and_then(|rest| rest.find("\n    }")) else {
            panic!("NewOrderSingle struct must be terminated");
        };
        let Some(body) = code.get(start..start + len) else {
            panic!("struct body must be sliceable");
        };
        assert!(!body.contains("pub symbol:"), "{body}");
        assert!(body.contains("pub cl_ord_id:"), "{body}");
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

    #[test]
    fn test_generate_fix44_struct_names_are_unique() {
        let code = generate(&CodeGenerator::new(), fix44());
        let mut names: Vec<&str> = Vec::new();
        for text in code.lines() {
            let trimmed = text.trim_start();
            if let Some(rest) = trimmed.strip_prefix("pub struct ")
                && let Some((name, _)) = rest.split_once(' ')
            {
                names.push(name);
            }
        }
        let unique: HashSet<&&str> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "struct names must not collide");
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

    #[test]
    fn test_generate_respects_configured_visibility() {
        let generator = CodeGenerator::with_config(GeneratorConfig {
            visibility: "pub(crate)".to_string(),
            ..GeneratorConfig::default()
        });
        let code = generate(&generator, fix44());
        assert!(code.contains("pub(crate) mod fields {"));
        assert!(code.contains("pub(crate) mod messages {"));
        assert!(code.contains("pub(crate) type FixDecimal"));
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
        dict.add_message(MessageDef {
            msg_type: "D".to_string(),
            name: "NewOrderSingle".to_string(),
            category: MessageCategory::App,
            fields: vec![SchemaFieldRef {
                tag: 11,
                name: "ClOrdID".to_string(),
                required: true,
            }],
            groups: Vec::new(),
            components: vec![ComponentRef::new("Looper", false)],
        });
        dict
    }

    #[test]
    fn test_generate_self_referencing_component_is_a_typed_error() {
        let dict = dict_with_component(ComponentDef {
            name: "Looper".to_string(),
            fields: Vec::new(),
            groups: Vec::new(),
            components: vec![ComponentRef::new("Looper", false)],
        });
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
        dict.add_message(MessageDef {
            msg_type: "D".to_string(),
            name: "NewOrderSingle".to_string(),
            category: MessageCategory::App,
            fields: Vec::new(),
            groups: Vec::new(),
            components: vec![ComponentRef::new("Nowhere", false)],
        });
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
        dict.add_message(MessageDef {
            msg_type: "D".to_string(),
            name: "NewOrderSingle".to_string(),
            category: MessageCategory::App,
            fields: vec![SchemaFieldRef {
                tag: 9999,
                name: "Mystery".to_string(),
                required: true,
            }],
            groups: Vec::new(),
            components: Vec::new(),
        });
        assert_eq!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::UnknownField {
                tag: 9999,
                scope: "message NewOrderSingle".to_string(),
            })
        );
    }

    #[test]
    fn test_generate_component_field_is_optional_even_when_required_inside() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(55, "Symbol", FieldType::String));
        dict.add_component(ComponentDef {
            name: "Instrument".to_string(),
            fields: vec![SchemaFieldRef {
                tag: 55,
                name: "Symbol".to_string(),
                required: true,
            }],
            groups: Vec::new(),
            components: Vec::new(),
        });
        dict.add_message(MessageDef {
            msg_type: "D".to_string(),
            name: "NewOrderSingle".to_string(),
            category: MessageCategory::App,
            fields: Vec::new(),
            groups: Vec::new(),
            components: vec![ComponentRef::new("Instrument", false)],
        });
        let code = generate(&CodeGenerator::new(), &dict);
        // The dictionary does not record whether the component reference is
        // required, so the safe representation is Option.
        assert!(code.contains("pub symbol: Option<String>,"));
    }

    #[test]
    fn test_generate_keeps_both_a_count_field_and_the_group_sharing_its_tag() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(453, "NoPartyIDs", FieldType::NumInGroup));
        dict.add_field(FieldDef::new(448, "PartyID", FieldType::String));
        dict.add_message(MessageDef {
            msg_type: "D".to_string(),
            name: "NewOrderSingle".to_string(),
            category: MessageCategory::App,
            // A dictionary that lists the count field directly as well as the
            // group it counts. Dropping either would lose information.
            fields: vec![SchemaFieldRef {
                tag: 453,
                name: "NoPartyIDs".to_string(),
                required: false,
            }],
            groups: vec![GroupDef {
                count_tag: 453,
                name: "NoPartyIDs".to_string(),
                delimiter_tag: 448,
                fields: vec![SchemaFieldRef {
                    tag: 448,
                    name: "PartyID".to_string(),
                    required: true,
                }],
                groups: Vec::new(),
                components: Vec::new(),
                required: false,
            }],
            components: Vec::new(),
        });
        let code = generate(&CodeGenerator::new(), &dict);
        assert!(code.contains("pub no_party_ids: Option<i64>,"), "{code}");
        assert!(
            code.contains("pub no_party_ids_453: Option<Vec<NewOrderSingleNoPartyIDsEntry>>,"),
            "{code}"
        );
    }

    #[test]
    fn test_generate_field_reached_twice_appears_once() {
        let mut dict = Dictionary::new(Version::Fix44);
        dict.add_field(FieldDef::new(55, "Symbol", FieldType::String));
        dict.add_component(ComponentDef {
            name: "Instrument".to_string(),
            fields: vec![SchemaFieldRef {
                tag: 55,
                name: "Symbol".to_string(),
                required: true,
            }],
            groups: Vec::new(),
            components: Vec::new(),
        });
        dict.add_message(MessageDef {
            msg_type: "D".to_string(),
            name: "NewOrderSingle".to_string(),
            category: MessageCategory::App,
            fields: vec![SchemaFieldRef {
                tag: 55,
                name: "Symbol".to_string(),
                required: true,
            }],
            groups: Vec::new(),
            components: vec![ComponentRef::new("Instrument", false)],
        });
        let code = generate(&CodeGenerator::new(), &dict);
        assert_eq!(code.matches("pub symbol:").count(), 1);
        // The direct reference wins, so it keeps its required-ness.
        assert!(code.contains("pub symbol: String,"));
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
        dict.add_component(ComponentDef {
            name: "Parties".to_string(),
            fields: Vec::new(),
            groups: vec![GroupDef {
                count_tag: 453,
                name: "NoPartyIDs".to_string(),
                delimiter_tag: 448,
                fields: vec![SchemaFieldRef {
                    tag: 448,
                    name: "PartyID".to_string(),
                    required: true,
                }],
                groups: Vec::new(),
                components: vec![ComponentRef::new("Parties", false)],
                required: false,
            }],
            components: Vec::new(),
        });
        dict.add_message(MessageDef {
            msg_type: "D".to_string(),
            name: "NewOrderSingle".to_string(),
            category: MessageCategory::App,
            fields: Vec::new(),
            groups: Vec::new(),
            components: vec![ComponentRef::new("Parties", false)],
        });
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
            dict.add_component(ComponentDef {
                name: format!("Comp{index}"),
                fields: Vec::new(),
                groups: Vec::new(),
                components: next,
            });
        }
        dict.add_message(MessageDef {
            msg_type: "D".to_string(),
            name: "NewOrderSingle".to_string(),
            category: MessageCategory::App,
            fields: vec![SchemaFieldRef {
                tag: 11,
                name: "ClOrdID".to_string(),
                required: true,
            }],
            groups: Vec::new(),
            components: vec![ComponentRef::new("Comp0", false)],
        });
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
        dict.add_message(MessageDef {
            msg_type: "D".to_string(),
            name: "NewOrderSingle".to_string(),
            category: MessageCategory::App,
            fields: vec![SchemaFieldRef {
                tag: 11,
                name: "Foo-Bar".to_string(),
                required: true,
            }],
            groups: Vec::new(),
            components: Vec::new(),
        });
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
        dict.add_message(MessageDef {
            msg_type: "D".to_string(),
            name: "New-Order".to_string(),
            category: MessageCategory::App,
            fields: Vec::new(),
            groups: Vec::new(),
            components: Vec::new(),
        });
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
        dict.add_message(MessageDef {
            msg_type: "D".to_string(),
            name: "NewOrderSingle".to_string(),
            category: MessageCategory::App,
            fields: Vec::new(),
            groups: vec![GroupDef {
                count_tag: 453,
                name: "No-Parties".to_string(),
                delimiter_tag: 448,
                fields: vec![SchemaFieldRef {
                    tag: 448,
                    name: "PartyID".to_string(),
                    required: true,
                }],
                groups: Vec::new(),
                components: Vec::new(),
                required: false,
            }],
            components: Vec::new(),
        });
        assert_eq!(
            CodeGenerator::new().generate(&dict),
            Err(GeneratorError::UnnameableItem {
                what: "group",
                name: "No-Parties".to_string(),
            })
        );
    }
}
