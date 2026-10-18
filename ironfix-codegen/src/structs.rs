/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The data structs of the default output, behind
//! [`CodeGenerator::generate`](crate::CodeGenerator::generate).
//!
//! # Model
//!
//! One struct per definition, referenced by name wherever it is used:
//!
//! - one struct per message, in the `messages` module, ordered by MsgType;
//! - one struct per component a message reaches (directly, through other
//!   components, or through group entries), in the `components` module,
//!   ordered by component name. A message, component or group entry that
//!   lists the component has one field of that type;
//! - one struct per repeating-group definition, named
//!   `<DeclaringOwner><GroupName>Entry` after the message, component or
//!   entry that declares it (the views' per-definition naming, ADR-0012,
//!   with an `Entry` suffix: the entry struct of the group whose view is
//!   `PartiesNoPartyIDsView` is `PartiesNoPartyIDsEntry`). It is emitted in
//!   its declaring owner's module, right after the owner.
//!
//! A struct lists its members in XML order (`members()`). A field is
//! required where its reference is required, a component field where its
//! component reference is, and a group field where its group definition is;
//! everything else is an `Option`. Nothing is flattened, so the output grows
//! with the number of definitions, not with how often they are reused.
//!
//! # Fail closed
//!
//! A pass over the messages first collects the components they reach and
//! checks the structure: an undefined component, a component that contains
//! itself (directly, through other components, or through a group entry), and
//! nesting past [`MAX_NESTING_DEPTH`] are errors. The structs are then built;
//! an undefined field or a name with no Rust identifier is an error there.
//!
//! The pass expands each component once, so the nesting depth is checked
//! along the first path that reaches a component, not along every path. A
//! component reached first near the top and later from deep inside another
//! component is not expanded again from there. The views
//! ([`CodeGenerator::generate_views`](crate::CodeGenerator::generate_views))
//! expand components in place along every path, so a dictionary can pass
//! [`CodeGenerator::generate`](crate::CodeGenerator::generate) and still fail
//! `generate_views` with [`GeneratorError::MaxDepthExceeded`]. Either way the
//! recursion is bounded.

use crate::generator::{
    DECIMAL_ALIAS, GeneratorError, MAX_NESTING_DEPTH, claim_ident, field_doc, field_type_to_rust,
    is_valid_ident, join_type, line, resolve_field_name, to_pascal_case, to_snake_case,
    to_type_ident, unique_type_name, wrap_optional,
};
use ironfix_dictionary::schema::{ComponentDef, Dictionary, GroupDef, MemberRef, MessageDef};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Name of the generated module holding the component structs.
const COMPONENTS_MODULE: &str = "components";

/// Suffix of a repeating-group entry struct's name.
const ENTRY_SUFFIX: &str = "Entry";

/// Suffix a component field takes when its name is already used in the
/// struct.
const COMPONENT_SUFFIX: &str = "component";

/// The generated module a struct is emitted into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Module {
    /// `messages`: the message structs and the entries of the groups they
    /// declare.
    Messages,
    /// `components`: the component structs and the entries of the groups
    /// they declare.
    Components,
}

/// A struct the generator will emit.
#[derive(Debug)]
struct StructModel {
    /// Doc comment for the struct.
    doc: String,
    /// Rust type name.
    name: String,
    /// Struct fields, in XML order.
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

/// The structs of the default output, per module, in emission order.
#[derive(Debug, Default)]
pub(crate) struct DataModel {
    /// The `messages` module.
    messages: Vec<StructModel>,
    /// The `components` module; empty when no message reaches a component.
    components: Vec<StructModel>,
}

impl DataModel {
    /// Whether any struct has a decimal field, so the file needs the alias.
    #[must_use]
    pub(crate) fn uses_decimal(&self) -> bool {
        uses_decimal(&self.messages) || uses_decimal(&self.components)
    }

    fn module_mut(&mut self, module: Module) -> &mut Vec<StructModel> {
        match module {
            Module::Messages => &mut self.messages,
            Module::Components => &mut self.components,
        }
    }
}

/// Whether any of `structs` has a decimal field.
#[must_use]
fn uses_decimal(structs: &[StructModel]) -> bool {
    structs
        .iter()
        .any(|model| model.fields.iter().any(|field| field.uses_decimal))
}

/// The message, component or group entry a struct is built for.
#[derive(Debug)]
struct Owner {
    /// The module the struct and the entries of its groups go into.
    module: Module,
    /// The struct's type name.
    name: String,
    /// Prefix of the type names of the groups it declares: the type name of
    /// a message or component, the base (the name without `Entry`) of a
    /// group entry.
    base: String,
    /// Doc comment for the struct.
    doc: String,
    /// For error messages, for example `message NewOrderSingle`.
    scope: String,
}

/// Builds the [`DataModel`].
struct Builder<'d> {
    dict: &'d Dictionary,
    /// [`GeneratorConfig::generate_components`](crate::GeneratorConfig::generate_components).
    expand_components: bool,
    /// Type name of each component a message reaches, by component name.
    component_types: HashMap<&'d str, String>,
    /// Type names taken in the `messages` module.
    message_names: HashSet<String>,
    /// Type names taken in the `components` module.
    component_names: HashSet<String>,
    model: DataModel,
}

/// Builds the structs of a dictionary.
///
/// With `expand_components` off, components are neither generated nor
/// referenced: a struct carries the fields and groups its definition lists
/// directly.
pub(crate) fn build(
    dict: &Dictionary,
    expand_components: bool,
) -> Result<DataModel, GeneratorError> {
    let mut messages: Vec<&MessageDef> = dict.messages().collect();
    messages.sort_by(|a, b| a.msg_type.cmp(&b.msg_type));

    // The alias is imported into each module that uses it, so no generated
    // type may take its name.
    let reserved: HashSet<String> = HashSet::from([DECIMAL_ALIAS.to_string()]);
    let mut builder = Builder {
        dict,
        expand_components,
        component_types: HashMap::new(),
        message_names: reserved.clone(),
        component_names: reserved,
        model: DataModel::default(),
    };

    // The components the messages reach, checked for cycles and depth.
    let mut reached: BTreeMap<&str, &ComponentDef> = BTreeMap::new();
    for message in &messages {
        let scope = format!("message {}", message.name);
        builder.reach(
            message.members().collect(),
            &scope,
            0,
            &mut Vec::new(),
            &mut reached,
        )?;
    }

    // Messages, then components, claim their names before any group entry.
    let mut message_types = Vec::with_capacity(messages.len());
    for message in &messages {
        let base = type_base(&message.name, "message")?;
        message_types.push(unique_type_name(
            &mut builder.message_names,
            &to_type_ident(&base),
        ));
    }
    let mut components: Vec<(&str, &ComponentDef, String)> = Vec::with_capacity(reached.len());
    for (&name, &component) in &reached {
        let base = type_base(name, "component")?;
        let ty = unique_type_name(&mut builder.component_names, &to_type_ident(&base));
        builder.component_types.insert(name, ty.clone());
        components.push((name, component, ty));
    }

    for (message, name) in messages.iter().zip(message_types) {
        let owner = Owner {
            module: Module::Messages,
            base: name.clone(),
            name,
            doc: format!("{} message (MsgType={}).", message.name, message.msg_type),
            scope: format!("message {}", message.name),
        };
        builder.build_owner(owner, message.members().collect(), 0)?;
    }
    for (name, component, ty) in components {
        let owner = Owner {
            module: Module::Components,
            base: ty.clone(),
            name: ty,
            doc: format!(
                "{name} component, one type shared by every message, component and group entry that lists it."
            ),
            scope: format!("component {name}"),
        };
        builder.build_owner(owner, component.members().collect(), 0)?;
    }

    Ok(builder.model)
}

impl<'d> Builder<'d> {
    /// Collects into `reached` every component `members` reach, through
    /// components and group entries alike.
    ///
    /// `stack` is the chain of components being expanded, so a component
    /// that contains itself is a [`GeneratorError::ComponentCycle`] with the
    /// path that closes it, even when the cycle passes through a group entry.
    /// A component is added to `reached` once fully expanded and is not
    /// expanded again. `depth` grows by one on every descent into a component
    /// or a group entry and is checked against [`MAX_NESTING_DEPTH`], so a
    /// deep but acyclic dictionary cannot overflow the stack.
    fn reach(
        &self,
        members: Vec<MemberRef<'d>>,
        scope: &str,
        depth: usize,
        stack: &mut Vec<String>,
        reached: &mut BTreeMap<&'d str, &'d ComponentDef>,
    ) -> Result<(), GeneratorError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(GeneratorError::MaxDepthExceeded {
                scope: scope.to_string(),
                limit: MAX_NESTING_DEPTH,
            });
        }
        let next = deeper(depth, scope)?;
        for member in members {
            match member {
                MemberRef::Field(_) => {}
                MemberRef::Group(group) => {
                    let group_scope = format!("group {} of {scope}", group.name);
                    self.reach(
                        group.members().collect(),
                        &group_scope,
                        next,
                        stack,
                        reached,
                    )?;
                }
                MemberRef::Component(reference) => {
                    if !self.expand_components {
                        continue;
                    }
                    let name = reference.name.as_str();
                    if stack.iter().any(|visited| visited == name) {
                        let mut path = stack.clone();
                        path.push(name.to_string());
                        return Err(GeneratorError::ComponentCycle {
                            name: name.to_string(),
                            path: path.join(" -> "),
                        });
                    }
                    if reached.contains_key(name) {
                        continue;
                    }
                    let component = self.dict.get_component(name).ok_or_else(|| {
                        GeneratorError::UnknownComponent {
                            name: name.to_string(),
                            scope: scope.to_string(),
                        }
                    })?;
                    stack.push(name.to_string());
                    self.reach(
                        component.members().collect(),
                        &format!("component {name}"),
                        next,
                        stack,
                        reached,
                    )?;
                    stack.pop();
                    reached.insert(name, component);
                }
            }
        }
        Ok(())
    }

    /// Builds the struct of `owner` from its members, then, right after it,
    /// the entry struct of each group it declares (recursively).
    ///
    /// `depth` grows by one per nested group entry and is checked against
    /// [`MAX_NESTING_DEPTH`].
    fn build_owner(
        &mut self,
        owner: Owner,
        members: Vec<MemberRef<'d>>,
        depth: usize,
    ) -> Result<(), GeneratorError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(GeneratorError::MaxDepthExceeded {
                scope: owner.scope,
                limit: MAX_NESTING_DEPTH,
            });
        }
        let next = deeper(depth, &owner.scope)?;

        let mut fields: Vec<StructFieldModel> = Vec::with_capacity(members.len());
        // Field tags and group count tags are tracked apart: a dictionary that
        // lists a count field directly *and* as a group keeps both, one as the
        // count and one as the entries, rather than losing the group.
        let mut seen_field_tags: HashSet<u32> = HashSet::with_capacity(members.len());
        let mut seen_group_tags: HashSet<u32> = HashSet::new();
        let mut seen_components: HashSet<&str> = HashSet::new();
        let mut used_names: HashSet<String> = HashSet::with_capacity(members.len());
        // The groups this owner declares: (definition, base, entry type).
        let mut entries: Vec<(&'d GroupDef, String, String)> = Vec::new();

        for member in members {
            match member {
                MemberRef::Field(field) => {
                    if !seen_field_tags.insert(field.tag) {
                        // A tag listed twice in one definition is one field.
                        continue;
                    }
                    let def = self.dict.get_field(field.tag).ok_or_else(|| {
                        GeneratorError::UnknownField {
                            tag: field.tag,
                            scope: owner.scope.clone(),
                        }
                    })?;
                    let ident = resolve_field_name(&mut used_names, &field.name, field.tag)?;
                    let base = field_type_to_rust(def.field_type);
                    fields.push(StructFieldModel {
                        doc: field_doc(def),
                        name: ident,
                        ty: wrap_optional(base, field.required),
                        uses_decimal: base == DECIMAL_ALIAS,
                    });
                }
                MemberRef::Group(group) => {
                    if !seen_group_tags.insert(group.count_tag) {
                        // A group listed twice in one definition is one field.
                        continue;
                    }
                    let candidate = join_type(&owner.base, &to_pascal_case(&group.name));
                    // The owner's base is already an identifier, so a
                    // punctuated group name is what would break it; reject it
                    // rather than emit a struct whose name will not compile.
                    if !is_valid_ident(&candidate) {
                        return Err(GeneratorError::UnnameableItem {
                            what: "group",
                            name: group.name.clone(),
                        });
                    }
                    let names = self.names_mut(owner.module);
                    let (base, entry) =
                        entry_names(names, &to_type_ident(&candidate), &group.name)?;
                    let ident = resolve_field_name(&mut used_names, &group.name, group.count_tag)?;
                    fields.push(StructFieldModel {
                        doc: format!(
                            "{} (tag {}) repeating group; its length is the count field.",
                            group.name, group.count_tag
                        ),
                        name: ident,
                        ty: wrap_optional(&format!("::std::vec::Vec<{entry}>"), group.required),
                        uses_decimal: false,
                    });
                    entries.push((group, base, entry));
                }
                MemberRef::Component(reference) => {
                    if !self.expand_components || !seen_components.insert(reference.name.as_str()) {
                        continue;
                    }
                    let ty = self
                        .component_types
                        .get(reference.name.as_str())
                        .ok_or_else(|| GeneratorError::UnknownComponent {
                            name: reference.name.clone(),
                            scope: owner.scope.clone(),
                        })?;
                    let path = match owner.module {
                        Module::Components => ty.clone(),
                        Module::Messages => format!("super::{COMPONENTS_MODULE}::{ty}"),
                    };
                    let ident = resolve_component_name(&mut used_names, &reference.name)?;
                    fields.push(StructFieldModel {
                        doc: format!("{} component.", reference.name),
                        name: ident,
                        ty: wrap_optional(&path, reference.required),
                        uses_decimal: false,
                    });
                }
            }
        }

        let module = owner.module;
        self.model.module_mut(module).push(StructModel {
            doc: owner.doc,
            name: owner.name.clone(),
            fields,
        });

        for (group, base, entry) in entries {
            let entry_owner = Owner {
                module,
                doc: format!(
                    "One entry of the {} (tag {}) repeating group in {}.",
                    group.name, group.count_tag, owner.name
                ),
                scope: format!("group {} of {}", group.name, owner.scope),
                name: entry,
                base,
            };
            self.build_owner(entry_owner, group.members().collect(), next)?;
        }
        Ok(())
    }

    /// The type names taken in `module`.
    fn names_mut(&mut self, module: Module) -> &mut HashSet<String> {
        match module {
            Module::Messages => &mut self.message_names,
            Module::Components => &mut self.component_names,
        }
    }
}

/// Returns the PascalCase type-name base of a dictionary name, or
/// [`GeneratorError::UnnameableItem`].
fn type_base(name: &str, what: &'static str) -> Result<String, GeneratorError> {
    let base = to_pascal_case(name);
    if is_valid_ident(&base) {
        Ok(base)
    } else {
        Err(GeneratorError::UnnameableItem {
            what,
            name: name.to_string(),
        })
    }
}

/// Returns the nesting depth one level below `depth`.
///
/// # Errors
///
/// [`GeneratorError::MaxDepthExceeded`] naming `scope` if the depth does
/// not fit a `usize`. Callers check `depth` against [`MAX_NESTING_DEPTH`]
/// first, so this is a backstop.
fn deeper(depth: usize, scope: &str) -> Result<usize, GeneratorError> {
    depth
        .checked_add(1)
        .ok_or_else(|| GeneratorError::MaxDepthExceeded {
            scope: scope.to_string(),
            limit: MAX_NESTING_DEPTH,
        })
}

/// Claims the names of a group entry in `used`: its base, which the groups
/// nested in it are named after, and its struct name, the base followed by
/// `Entry`. A numeric suffix after `candidate` settles a collision with
/// either.
///
/// # Errors
///
/// [`GeneratorError::UnnameableItem`] for the group `group_name` if the
/// suffix runs out of `usize` values before a free pair of names is found.
/// Each taken name blocks at most two suffixes, so the loop ends long before.
fn entry_names(
    used: &mut HashSet<String>,
    candidate: &str,
    group_name: &str,
) -> Result<(String, String), GeneratorError> {
    let mut suffix = 1usize;
    loop {
        let base = if suffix == 1 {
            candidate.to_string()
        } else {
            join_type(candidate, &suffix.to_string())
        };
        let entry = join_type(&base, ENTRY_SUFFIX);
        if !used.contains(&base) && !used.contains(&entry) {
            used.insert(base.clone());
            used.insert(entry.clone());
            return Ok((base, entry));
        }
        suffix = suffix
            .checked_add(1)
            .ok_or_else(|| GeneratorError::UnnameableItem {
                what: "group",
                name: group_name.to_string(),
            })?;
    }
}

/// Resolves the identifier of a component field, unique within its struct:
/// the component name in snake case, then with a `_component` suffix, then
/// with a numeric one, each checked and reserved once escaped
/// ([`claim_ident`]), so `Crate` (`crate_`) and a `Crate_` field, or the
/// components `Self` (`self_`) and `Self_`, get distinct fields.
///
/// # Errors
///
/// [`GeneratorError::UnnameableItem`] if the name is not an identifier in
/// snake case, or if no unique identifier is left for it.
fn resolve_component_name(
    used: &mut HashSet<String>,
    name: &str,
) -> Result<String, GeneratorError> {
    let base = to_snake_case(name);
    if !is_valid_ident(&base) {
        return Err(GeneratorError::UnnameableItem {
            what: "component",
            name: name.to_string(),
        });
    }
    claim_ident(used, &base, COMPONENT_SUFFIX).ok_or_else(|| GeneratorError::UnnameableItem {
        what: "component",
        name: name.to_string(),
    })
}

/// Emits the `messages` module and, when a message reaches a component, the
/// `components` module.
pub(crate) fn emit(code: &mut String, visibility: &str, model: &DataModel) {
    emit_module(
        code,
        visibility,
        "messages",
        "Message type definitions, and the entries of the repeating groups messages declare.",
        &model.messages,
    );
    if !model.components.is_empty() {
        line(code, "");
        emit_module(
            code,
            visibility,
            COMPONENTS_MODULE,
            "Component type definitions, one per component a message reaches, and the entries of the repeating groups components declare.",
            &model.components,
        );
    }
}

/// Emits one module of structs.
fn emit_module(
    code: &mut String,
    visibility: &str,
    module: &str,
    doc: &str,
    structs: &[StructModel],
) {
    line(code, &format!("/// {doc}"));
    line(code, &format!("{visibility} mod {module} {{"));
    if uses_decimal(structs) {
        line(code, &format!("    use super::{DECIMAL_ALIAS};"));
        line(code, "");
    }

    for model in structs {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_names_claims_base_and_entry() {
        let mut used = HashSet::new();
        assert_eq!(
            entry_names(&mut used, "PartiesNoPartyIDs", "NoPartyIDs"),
            Ok((
                "PartiesNoPartyIDs".to_string(),
                "PartiesNoPartyIDsEntry".to_string()
            ))
        );
        // The same candidate again takes a numeric suffix, on both names.
        assert_eq!(
            entry_names(&mut used, "PartiesNoPartyIDs", "NoPartyIDs"),
            Ok((
                "PartiesNoPartyIDs2".to_string(),
                "PartiesNoPartyIDs2Entry".to_string()
            ))
        );
    }

    #[test]
    fn test_entry_names_steps_past_a_taken_entry_name() {
        // A type already named like the entry struct pushes both names on.
        let mut used = HashSet::from(["XNoAEntry".to_string()]);
        assert_eq!(
            entry_names(&mut used, "XNoA", "NoA"),
            Ok(("XNoA2".to_string(), "XNoA2Entry".to_string()))
        );
    }

    #[test]
    fn test_deeper_is_a_typed_error_at_the_end_of_usize() {
        assert_eq!(deeper(3, "message D"), Ok(4));
        assert_eq!(
            deeper(usize::MAX, "message D"),
            Err(GeneratorError::MaxDepthExceeded {
                scope: "message D".to_string(),
                limit: MAX_NESTING_DEPTH,
            })
        );
    }

    #[test]
    fn test_resolve_component_name_suffixes_a_taken_name() {
        let mut used = HashSet::from(["instrument".to_string()]);
        assert_eq!(
            resolve_component_name(&mut used, "Instrument"),
            Ok("instrument_component".to_string())
        );
        assert_eq!(
            resolve_component_name(&mut used, "Instrument"),
            Ok("instrument_component_2".to_string())
        );
        // A keyword becomes a raw identifier.
        assert_eq!(
            resolve_component_name(&mut used, "Type"),
            Ok("r#type".to_string())
        );
        assert_eq!(
            resolve_component_name(&mut used, "Bad-Name"),
            Err(GeneratorError::UnnameableItem {
                what: "component",
                name: "Bad-Name".to_string(),
            })
        );
    }
}
