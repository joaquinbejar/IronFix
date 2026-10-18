/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Opt-in generation of borrowed views, enumerations and writers, behind
//! [`CodeGenerator::generate_views`](crate::CodeGenerator::generate_views).
//!
//! # Model
//!
//! Each message body, and each repeating-group entry, is expanded into one
//! *level* of members the way `ironfix_dictionary`'s group reader and
//! validator expand it: fields, then groups, then components (recursively, in
//! that order). A member reached through components is required only when
//! every component reference on the way to it is required, as in the
//! validator. A field reached twice is one member, required if any occurrence
//! is; of two groups sharing a count tag the first wins; a plain field whose
//! tag is also a group's count tag gives way to the group.
//!
//! A group *definition* is modelled once, wherever it is reached from: the
//! group a component declares gets one layout constant, one view and one
//! writer, shared by every message that uses the component. Its name is the
//! declaring component (or message, or enclosing group) followed by the group
//! name, for example `PartiesNoPartyIDs`.
//!
//! The static layouts mirror `MessageLayout`: a group's members are its
//! delimiter, its fields and its nested groups' count tags, components
//! flattened; a message's top-level set is its header, trailer and body
//! groups.
//!
//! # Lint-clean output
//!
//! The output must compile under `-D warnings` and the default clippy lints
//! with no `#[allow]`, for any dictionary. So helpers are emitted only when
//! something uses them, imports likewise, every `pub` item is documented,
//! enumeration variants never start or end with their enumeration's name
//! (`clippy::enum_variant_names`) and are never all-capital acronyms
//! (`clippy::upper_case_acronyms`), and an accessor never takes a name whose
//! prefix clippy ties to another receiver (`from_`, `into_`, `to_`).

use crate::generator::{
    GeneratorError, MAX_NESTING_DEPTH, is_keyword, is_valid_ident, line, to_field_ident,
    to_pascal_case, to_screaming_snake_case, to_snake_case, to_type_ident, unique_name,
    unique_type_name,
};
// `FieldRef` also names a zero-copy wire field in `ironfix-core`; this is the
// schema-side one (tag, name, required).
use ironfix_dictionary::schema::FieldRef as SchemaFieldRef;
use ironfix_dictionary::schema::{
    ComponentRef, Dictionary, FieldDef, FieldType, GroupDef, MessageDef,
};
use std::collections::{BTreeSet, HashMap, HashSet};

/// Name of the fallback variant every generated enumeration carries.
const OTHER: &str = "Other";

/// Prefix of a variant name built from a wire value rather than from its
/// description.
const VALUE_PREFIX: &str = "Value";

/// Prefix of the numbered fallback variant names of an enumeration whose
/// name starts with `V`, so they never start with it.
const FALLBACK_PREFIX: &str = "Code";

/// Names an accessor or writer field never takes: the generated types' own
/// methods, and `clone` / `fmt`, which would shadow a derived or implemented
/// trait method.
const RESERVED_MEMBER_NAMES: [&str; 10] = [
    "check",
    "clone",
    "emit",
    "entry",
    "fmt",
    "from_message",
    "get",
    "message",
    "wrap",
    "write",
];

/// Accessor name prefixes that `clippy::wrong_self_convention` ties to a
/// receiver other than `&self`; a member name starting with one is prefixed
/// with `field_`.
const CONVENTION_PREFIXES: [&str; 3] = ["from_", "into_", "to_"];

/// Type names the `enums` module keeps for itself.
const RESERVED_ENUM_NAMES: [&str; 2] = ["Tokens", OTHER];

/// Variant names of the prelude's `Option` and `Result`: an enumeration
/// variant spelled the same would shadow them under a glob import, so FIX 4.4
/// EncryptMethod `NONE` (0) is `None0`.
const PRELUDE_VARIANTS: [&str; 4] = ["None", "Some", "Ok", "Err"];

/// The ironfix-dictionary versions the generated code compiles against, as a
/// Cargo requirement: `GroupSet::field` is new after 0.4.1. Set it to the
/// release that ships it when that release is cut.
const MIN_DICTIONARY_VERSION: &str = ">0.4.1";

/// Size, in bytes, of the stack buffer the writers format numbers into: room
/// for any `rust_decimal::Decimal`, `i64`, `u64` or `usize`.
const FORMAT_BUFFER_BYTES: usize = 64;

/// What an accessor returns and a writer takes for one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A string, borrowed.
    Str,
    /// Raw bytes (`data`, `XMLData`), borrowed.
    Bytes,
    /// One ASCII character.
    Char,
    /// `Y` or `N`.
    Bool,
    /// A signed integer.
    Int,
    /// A non-negative integer: a length, sequence number, count, tag or day.
    UInt,
    /// A decimal: price, quantity, amount, percentage, float.
    Decimal,
    /// One value of the enumeration generated for this tag.
    Enum(u32),
    /// The space-separated values of the enumeration generated for this tag.
    Tokens(u32),
}

impl Kind {
    /// Decides the kind of a field from its type and declared values.
    ///
    /// A field with declared values becomes an enumeration, except a
    /// `Boolean`, whose two values `bool` already represents exactly, and a
    /// `data` field, whose value is raw bytes framed by its length.
    fn of(def: &FieldDef) -> Self {
        if matches!(def.field_type, FieldType::Data | FieldType::XmlData) {
            return Self::Bytes;
        }
        let declared = def.values.as_ref().is_some_and(|values| !values.is_empty());
        if declared && def.field_type != FieldType::Boolean {
            return if def.field_type.is_multi_value() {
                Self::Tokens(def.tag)
            } else {
                Self::Enum(def.tag)
            };
        }
        match def.field_type {
            FieldType::Int => Self::Int,
            FieldType::Length
            | FieldType::SeqNum
            | FieldType::NumInGroup
            | FieldType::TagNum
            | FieldType::DayOfMonth => Self::UInt,
            FieldType::Float
            | FieldType::Qty
            | FieldType::Price
            | FieldType::PriceOffset
            | FieldType::Amt
            | FieldType::Percentage => Self::Decimal,
            FieldType::Char => Self::Char,
            FieldType::Boolean => Self::Bool,
            FieldType::Data | FieldType::XmlData => Self::Bytes,
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
            | FieldType::Reserved => Self::Str,
        }
    }

    /// The tag of the enumeration this kind reads, if any.
    const fn enum_tag(self) -> Option<u32> {
        match self {
            Self::Enum(tag) | Self::Tokens(tag) => Some(tag),
            _ => None,
        }
    }

    /// Whether a writer field of this kind borrows (and so needs a lifetime).
    const fn borrows(self) -> bool {
        matches!(
            self,
            Self::Str | Self::Bytes | Self::Enum(_) | Self::Tokens(_)
        )
    }

    /// The generated view helper that reads a kind whose value can be
    /// malformed, checked against the validator's grammar, and its Rust type;
    /// `None` for a kind that reads every value.
    const fn conversion(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::Str => Some(("text", "&'a str")),
            Self::Char => Some(("character", "char")),
            Self::Bool => Some(("boolean", "bool")),
            Self::Int => Some(("int", "i64")),
            Self::UInt => Some(("uint", "u64")),
            Self::Decimal => Some(("decimal", "Decimal")),
            Self::Bytes | Self::Enum(_) | Self::Tokens(_) => None,
        }
    }
}

/// Whether a field is half of a LENGTH/DATA pair.
///
/// The dictionary does not name the pairs; it lists a `data` (or `XMLData`)
/// field right after the `Length` field that frames it, so a `data` field is
/// paired with the `Length` field immediately before it in the same field
/// list. Every pair of the embedded dictionaries is listed that way, and a
/// `data` field listed any other way is a
/// [`GeneratorError::UnpairedDataField`]. The `Length` half may be a group's
/// delimiter (FIX 5.0 SP2 `NoPaymentStreamFormulas` entries open with
/// `PaymentStreamFormulaLength`): the pair is kept, its data is required, and
/// the writer emits the pair first, so the length still opens the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pair {
    /// Not part of a pair.
    None,
    /// A `Length` field framing the `data` field with this tag. A writer
    /// derives it from the data rather than taking it.
    Length(u32),
    /// A `data` field framed by the `Length` field with this tag.
    Data(u32),
}

/// A field of a level.
#[derive(Debug, Clone)]
struct FieldMember {
    tag: u32,
    /// The name the dictionary reference spells.
    name: String,
    required: bool,
    kind: Kind,
    /// The field's FIX type, whose grammar a view checks before converting.
    field_type: FieldType,
    /// Doc line: name, tag and description.
    doc: String,
    pair: Pair,
}

/// A repeating group of a level.
#[derive(Debug, Clone)]
struct GroupMember {
    count_tag: u32,
    /// The group name the dictionary spells.
    name: String,
    /// Index of the group definition in [`Model::sites`].
    site: usize,
    required: bool,
}

/// A member of a level.
#[derive(Debug, Clone)]
enum Member {
    Field(FieldMember),
    Group(GroupMember),
}

impl Member {
    /// The field's tag or the group's count tag.
    const fn tag(&self) -> u32 {
        match self {
            Self::Field(field) => field.tag,
            Self::Group(group) => group.count_tag,
        }
    }

    /// Marks the member required.
    const fn set_required(&mut self) {
        match self {
            Self::Field(field) => field.required = true,
            Self::Group(group) => group.required = true,
        }
    }
}

/// Collects the members of one level as the expansion reaches them.
#[derive(Debug, Default)]
struct LevelBuilder {
    members: Vec<Member>,
    /// Position of each field member, by tag.
    fields: HashMap<u32, usize>,
    /// Count tags of the group members.
    group_tags: HashSet<u32>,
    /// Every tag reached at this level, count tags included: the layout's
    /// member list once sorted.
    tags: Vec<u32>,
}

impl LevelBuilder {
    fn add_field(&mut self, member: FieldMember) {
        self.tags.push(member.tag);
        if let Some(&index) = self.fields.get(&member.tag) {
            if let Some(Member::Field(existing)) = self.members.get_mut(index) {
                existing.required |= member.required;
                if existing.pair == Pair::None {
                    existing.pair = member.pair;
                }
            }
            return;
        }
        self.fields.insert(member.tag, self.members.len());
        self.members.push(Member::Field(member));
    }

    /// Marks the field `tag`, already added, as the `Length` of `data_tag`.
    fn pair_length(&mut self, tag: u32, data_tag: u32) {
        let member = self
            .fields
            .get(&tag)
            .and_then(|index| self.members.get_mut(*index));
        if let Some(Member::Field(field)) = member
            && field.pair == Pair::None
        {
            field.pair = Pair::Length(data_tag);
        }
    }

    fn add_group(&mut self, member: GroupMember) {
        self.tags.push(member.count_tag);
        if self.group_tags.insert(member.count_tag) {
            self.members.push(Member::Group(member));
        }
    }

    /// Finishes the level: drops the plain fields a group supersedes and
    /// sorts the layout lists. `delimiter` joins the member tags of a group
    /// entry.
    fn finish(self, delimiter: Option<u32>) -> Level {
        let group_tags = self.group_tags;
        let members: Vec<Member> = self
            .members
            .into_iter()
            .filter(|member| match member {
                Member::Field(field) => !group_tags.contains(&field.tag),
                Member::Group(_) => true,
            })
            .collect();
        let mut groups: Vec<(u32, usize)> = members
            .iter()
            .filter_map(|member| match member {
                Member::Group(group) => Some((group.count_tag, group.site)),
                Member::Field(_) => None,
            })
            .collect();
        groups.sort_unstable_by_key(|(count_tag, _)| *count_tag);
        let mut spec_members = self.tags;
        spec_members.extend(delimiter);
        spec_members.sort_unstable();
        spec_members.dedup();
        Level {
            members,
            idents: Vec::new(),
            spec_members,
            groups,
        }
    }
}

/// One finished level: a message body or a group entry.
#[derive(Debug, Default)]
struct Level {
    /// Members in write order (an entry's delimiter first).
    members: Vec<Member>,
    /// Rust identifier of each member, unique within the level.
    idents: Vec<String>,
    /// Tags that may appear at this level, sorted and unique.
    spec_members: Vec<u32>,
    /// Groups of the level as `(count tag, site)`, sorted by count tag.
    groups: Vec<(u32, usize)>,
}

impl Level {
    /// Members paired with their identifiers.
    fn named(&self) -> impl Iterator<Item = (&Member, &str)> {
        self.members
            .iter()
            .zip(self.idents.iter().map(String::as_str))
    }
}

/// One repeating-group definition.
#[derive(Debug)]
struct Site {
    /// Unique PascalCase base of its type names.
    base: String,
    /// Unique name of its layout constant.
    konst: String,
    /// The group name the dictionary spells.
    name: String,
    count_tag: u32,
    delimiter_tag: u32,
    /// Where the group is declared, for docs.
    owner_doc: String,
    entry: Level,
    /// Whether a message body reaches it, so it gets a view and a writer.
    in_body: bool,
}

/// One message.
#[derive(Debug)]
struct MessageModel {
    name: String,
    msg_type: String,
    base: String,
    /// Unique name of its layout constant.
    konst: String,
    body: Level,
    /// The groups that may open at its top level, header and trailer
    /// included, sorted by count tag.
    top_groups: Vec<usize>,
}

/// One enumeration.
#[derive(Debug)]
struct EnumModel {
    tag: u32,
    field: String,
    name: String,
    multi: bool,
    variants: Vec<Variant>,
}

/// One declared value of an enumeration.
#[derive(Debug)]
struct Variant {
    name: String,
    value: String,
    description: String,
}

/// Everything the emitters need.
#[derive(Debug)]
struct Model {
    version: String,
    messages: Vec<MessageModel>,
    sites: Vec<Site>,
    enums: Vec<EnumModel>,
}

impl Model {
    fn site(&self, index: usize) -> Option<&Site> {
        self.sites.get(index)
    }

    fn enum_name(&self, tag: u32) -> &str {
        self.enums
            .iter()
            .find(|model| model.tag == tag)
            .map_or("", |model| model.name.as_str())
    }

    /// The members of every level that gets a view and a writer.
    fn body_levels(&self) -> impl Iterator<Item = &Level> {
        self.messages.iter().map(|message| &message.body).chain(
            self.sites
                .iter()
                .filter(|site| site.in_body)
                .map(|site| &site.entry),
        )
    }

    fn body_fields(&self) -> impl Iterator<Item = &FieldMember> {
        self.body_levels()
            .flat_map(|level| level.members.iter())
            .filter_map(|member| match member {
                Member::Field(field) => Some(field),
                Member::Group(_) => None,
            })
    }
}

/// The parts of a message, component or group that expand into a level.
#[derive(Debug, Clone, Copy)]
struct Part<'d> {
    fields: &'d [SchemaFieldRef],
    groups: &'d [GroupDef],
    components: &'d [ComponentRef],
}

/// Where an expansion is.
#[derive(Debug)]
struct Ctx<'c> {
    /// For error messages, for example `message NewOrderSingle`.
    scope: &'c str,
    /// Type-name prefix of the groups declared here.
    owner: &'c str,
    /// For docs, for example `the Parties component`.
    owner_doc: &'c str,
    /// Whether requiredness is meaningful here (every component reference on
    /// the way was required).
    required: bool,
    depth: usize,
}

/// Builds the [`Model`].
struct Builder<'d> {
    dict: &'d Dictionary,
    sites: Vec<Site>,
    /// Site of each group definition already reached, by address: a
    /// definition is one value in the borrowed dictionary wherever it is
    /// reached from.
    site_index: HashMap<*const GroupDef, usize>,
    /// Type-name bases in use.
    bases: HashSet<String>,
}

impl<'d> Builder<'d> {
    /// Expands `part` into `level`.
    fn expand(
        &mut self,
        level: &mut LevelBuilder,
        part: Part<'d>,
        ctx: &Ctx<'_>,
        stack: &mut Vec<String>,
    ) -> Result<(), GeneratorError> {
        if ctx.depth > MAX_NESTING_DEPTH {
            return Err(GeneratorError::MaxDepthExceeded {
                scope: ctx.scope.to_string(),
                limit: MAX_NESTING_DEPTH,
            });
        }

        // The `Length` field listed right before a `data` field frames it; a
        // `data` field without one cannot be written with its count.
        let mut previous: Option<&FieldDef> = None;
        for field in part.fields {
            let def = self.field_def(field.tag, ctx.scope)?;
            let mut member = field_member(def, &field.name, ctx.required && field.required);
            if member.kind == Kind::Bytes {
                match previous {
                    Some(length) if length.field_type == FieldType::Length => {
                        member.pair = Pair::Data(length.tag);
                        level.pair_length(length.tag, def.tag);
                    }
                    _ => {
                        return Err(GeneratorError::UnpairedDataField {
                            tag: def.tag,
                            scope: ctx.scope.to_string(),
                        });
                    }
                }
            }
            level.add_field(member);
            previous = Some(def);
        }

        for group in part.groups {
            if level.group_tags.contains(&group.count_tag) {
                // The same count tag reached twice: the first group wins.
                level.tags.push(group.count_tag);
                continue;
            }
            let site = self.site(group, ctx, stack)?;
            level.add_group(GroupMember {
                count_tag: group.count_tag,
                name: group.name.clone(),
                site,
                required: ctx.required && group.required,
            });
        }

        for reference in part.components {
            let name = &reference.name;
            if stack.iter().any(|visited| visited == name) {
                let mut path = stack.clone();
                path.push(name.clone());
                return Err(GeneratorError::ComponentCycle {
                    name: name.clone(),
                    path: path.join(" -> "),
                });
            }
            let component =
                self.dict
                    .get_component(name)
                    .ok_or_else(|| GeneratorError::UnknownComponent {
                        name: name.clone(),
                        scope: ctx.scope.to_string(),
                    })?;
            let owner = type_base(name, "component")?;
            let scope = format!("component {name}");
            let owner_doc = format!("the {name} component");
            stack.push(name.clone());
            self.expand(
                level,
                Part {
                    fields: &component.fields,
                    groups: &component.groups,
                    components: &component.components,
                },
                &Ctx {
                    scope: &scope,
                    owner: &owner,
                    owner_doc: &owner_doc,
                    required: ctx.required && reference.required,
                    depth: ctx.depth + 1,
                },
                stack,
            )?;
            stack.pop();
        }

        Ok(())
    }

    /// Returns the definition of field `tag`, or
    /// [`GeneratorError::UnknownField`] naming `scope`.
    fn field_def(&self, tag: u32, scope: &str) -> Result<&'d FieldDef, GeneratorError> {
        self.dict
            .get_field(tag)
            .ok_or_else(|| GeneratorError::UnknownField {
                tag,
                scope: scope.to_string(),
            })
    }

    /// Returns the site of a group definition, building it on first reach.
    ///
    /// `stack` is the chain of components reaching it, so a cycle that closes
    /// through the group (component A -> group -> component A) is caught by
    /// [`Builder::expand`]: a definition can only be reached again from inside
    /// itself through the component that declares it.
    fn site(
        &mut self,
        group: &'d GroupDef,
        ctx: &Ctx<'_>,
        stack: &mut Vec<String>,
    ) -> Result<usize, GeneratorError> {
        let key = std::ptr::from_ref(group);
        if let Some(index) = self.site_index.get(&key) {
            return Ok(*index);
        }
        let candidate = format!("{}{}", ctx.owner, to_pascal_case(&group.name));
        if !is_valid_ident(&candidate) {
            return Err(GeneratorError::UnnameableItem {
                what: "group",
                name: group.name.clone(),
            });
        }
        let base = unique_type_name(&mut self.bases, &to_type_ident(&candidate));
        let index = self.sites.len();
        self.sites.push(Site {
            base: base.clone(),
            konst: String::new(),
            name: group.name.clone(),
            count_tag: group.count_tag,
            delimiter_tag: group.delimiter_tag,
            owner_doc: ctx.owner_doc.to_string(),
            entry: Level::default(),
            in_body: false,
        });
        self.site_index.insert(key, index);

        let scope = format!("group {} of {}", group.name, ctx.scope);
        let owner_doc = format!("an entry of the {} group", group.name);
        let mut level = LevelBuilder::default();
        self.expand(
            &mut level,
            Part {
                fields: &group.fields,
                groups: &group.groups,
                components: &group.components,
            },
            &Ctx {
                scope: &scope,
                owner: &base,
                owner_doc: &owner_doc,
                required: true,
                depth: ctx.depth + 1,
            },
            stack,
        )?;
        let entry = self.finish_entry(level, group, &scope)?;
        if let Some(site) = self.sites.get_mut(index) {
            site.entry = entry;
        }
        Ok(index)
    }

    /// Finishes a group entry: its delimiter first and required (it opens
    /// every entry), synthesised from the field definition when no member
    /// carries it. A delimiter that is the length of a LENGTH/DATA pair keeps
    /// the pair, with its data right after it and required; a `data`
    /// delimiter is a [`GeneratorError::UnpairedDataField`].
    fn finish_entry(
        &self,
        builder: LevelBuilder,
        group: &GroupDef,
        scope: &str,
    ) -> Result<Level, GeneratorError> {
        let delimiter_tag = group.delimiter_tag;
        let mut level = builder.finish(Some(delimiter_tag));
        let (leading, rest): (Vec<Member>, Vec<Member>) = level
            .members
            .into_iter()
            .partition(|member| member.tag() == delimiter_tag);
        let mut delimiter = match leading.into_iter().next() {
            Some(member) => member,
            None => {
                let def = self.field_def(delimiter_tag, scope)?;
                Member::Field(field_member(def, &def.name, true))
            }
        };
        delimiter.set_required();
        let mut members = Vec::with_capacity(rest.len() + 1);
        match &delimiter {
            // The delimiter is the length of a pair (FIX 5.0 SP2
            // NoPaymentStreamFormulas): the writer derives it from the data
            // and writes the pair first, so its data comes right after it and
            // is required, and the length still opens the entry.
            Member::Field(FieldMember {
                pair: Pair::Length(data_tag),
                ..
            }) => {
                let data_tag = *data_tag;
                let (data, others): (Vec<Member>, Vec<Member>) = rest
                    .into_iter()
                    .partition(|member| member.tag() == data_tag);
                members.push(delimiter);
                for mut member in data {
                    member.set_required();
                    members.push(member);
                }
                members.extend(others);
            }
            // A data field cannot open an entry: its length would have to be
            // written before the delimiter.
            Member::Field(field) if field.kind == Kind::Bytes => {
                return Err(GeneratorError::UnpairedDataField {
                    tag: field.tag,
                    scope: scope.to_string(),
                });
            }
            _ => {
                members.push(delimiter);
                members.extend(rest);
            }
        }
        level.members = members;
        name_members(&mut level)?;
        Ok(level)
    }

    /// Builds the sites of the header and trailer groups.
    fn envelope(&mut self) -> Result<Vec<usize>, GeneratorError> {
        let dict = self.dict;
        let mut sites = Vec::with_capacity(dict.header_groups.len() + dict.trailer_groups.len());
        for (groups, owner, owner_doc, scope) in [
            (
                &dict.header_groups,
                "Header",
                "the standard header",
                "header",
            ),
            (
                &dict.trailer_groups,
                "Trailer",
                "the standard trailer",
                "trailer",
            ),
        ] {
            let ctx = Ctx {
                scope,
                owner,
                owner_doc,
                required: true,
                depth: 0,
            };
            for group in groups {
                sites.push(self.site(group, &ctx, &mut Vec::new())?);
            }
        }
        Ok(sites)
    }

    /// Builds the model of one message.
    fn message(
        &mut self,
        def: &'d MessageDef,
        base: String,
        envelope: &[usize],
    ) -> Result<MessageModel, GeneratorError> {
        let scope = format!("message {}", def.name);
        let owner_doc = format!("the {} message", def.name);
        let mut level = LevelBuilder::default();
        self.expand(
            &mut level,
            Part {
                fields: &def.fields,
                groups: &def.groups,
                components: &def.components,
            },
            &Ctx {
                scope: &scope,
                owner: &base,
                owner_doc: &owner_doc,
                required: true,
                depth: 0,
            },
            &mut Vec::new(),
        )?;
        let mut body = level.finish(None);
        name_members(&mut body)?;

        // Header and trailer groups first, as the layout expands them: of two
        // groups sharing a count tag, the first expanded wins.
        let mut seen: HashSet<u32> = HashSet::new();
        let mut top: Vec<(u32, usize)> = Vec::new();
        for &site in envelope
            .iter()
            .chain(body.groups.iter().map(|(_, site)| site))
        {
            if let Some(model) = self.sites.get(site)
                && seen.insert(model.count_tag)
            {
                top.push((model.count_tag, site));
            }
        }
        top.sort_unstable_by_key(|(count_tag, _)| *count_tag);
        for &(_, site) in &body.groups {
            self.mark_in_body(site);
        }

        Ok(MessageModel {
            name: def.name.clone(),
            msg_type: def.msg_type.clone(),
            base,
            konst: String::new(),
            body,
            top_groups: top.into_iter().map(|(_, site)| site).collect(),
        })
    }

    /// Marks a site, and every group nested in it, as reached from a body.
    fn mark_in_body(&mut self, index: usize) {
        let mut pending = vec![index];
        while let Some(index) = pending.pop() {
            let Some(site) = self.sites.get_mut(index) else {
                continue;
            };
            if site.in_body {
                continue;
            }
            site.in_body = true;
            pending.extend(site.entry.groups.iter().map(|(_, nested)| *nested));
        }
    }
}

/// Builds the model of a dictionary.
fn build(dict: &Dictionary) -> Result<Model, GeneratorError> {
    let mut defs: Vec<&MessageDef> = dict.messages().collect();
    defs.sort_by(|a, b| a.msg_type.cmp(&b.msg_type));

    let mut builder = Builder {
        dict,
        sites: Vec::new(),
        site_index: HashMap::new(),
        bases: HashSet::with_capacity(defs.len()),
    };
    // Messages claim their names first, so a group's name never displaces
    // one.
    let mut bases = Vec::with_capacity(defs.len());
    for def in &defs {
        let base = type_base(&def.name, "message")?;
        bases.push(unique_type_name(&mut builder.bases, &to_type_ident(&base)));
    }
    let envelope = builder.envelope()?;
    let mut messages = Vec::with_capacity(defs.len());
    for (def, base) in defs.into_iter().zip(bases) {
        messages.push(builder.message(def, base, &envelope)?);
    }

    // Constant names: SCREAMING_SNAKE_CASE can fold two distinct bases onto
    // one name, so they are made unique on their own.
    let mut konsts: HashSet<String> = HashSet::new();
    for message in &mut messages {
        message.konst = unique_const(&mut konsts, &message.base);
    }
    let mut sites = builder.sites;
    for site in &mut sites {
        site.konst = unique_const(&mut konsts, &site.base);
    }

    let mut model = Model {
        version: dict.version.to_string(),
        messages,
        sites,
        enums: Vec::new(),
    };
    model.enums = build_enums(dict, &model)?;
    Ok(model)
}

/// Builds an enumeration for every field with declared values that a view or
/// writer uses, ordered by tag.
fn build_enums(dict: &Dictionary, model: &Model) -> Result<Vec<EnumModel>, GeneratorError> {
    let tags: BTreeSet<u32> = model
        .body_fields()
        .filter_map(|field| field.kind.enum_tag())
        .collect();
    let mut used: HashSet<String> = RESERVED_ENUM_NAMES
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut enums = Vec::with_capacity(tags.len());
    for tag in tags {
        let Some(def) = dict.get_field(tag) else {
            continue;
        };
        let base = to_pascal_case(&def.name);
        if !is_valid_ident(&base) {
            return Err(GeneratorError::UnnameableItem {
                what: "field",
                name: def.name.clone(),
            });
        }
        let name = unique_type_name(&mut used, &to_type_ident(&soften_acronym(&base)));
        let mut values: Vec<(&String, &String)> =
            def.values.iter().flat_map(|values| values.iter()).collect();
        values.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let names = variant_names(
            &name,
            values
                .iter()
                .map(|(value, description)| (value.as_str(), description.as_str())),
        );
        let variants = values
            .into_iter()
            .zip(names)
            .map(|((value, description), name)| Variant {
                name,
                value: value.clone(),
                description: description.clone(),
            })
            .collect();
        enums.push(EnumModel {
            tag,
            field: def.name.clone(),
            name,
            multi: def.field_type.is_multi_value(),
            variants,
        });
    }
    Ok(enums)
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

/// Returns a constant name for `base`, unique in `used`.
fn unique_const(used: &mut HashSet<String>, base: &str) -> String {
    let candidate = to_screaming_snake_case(base);
    if used.insert(candidate.clone()) {
        return candidate;
    }
    let mut suffix = 2usize;
    loop {
        let name = format!("{candidate}_{suffix}");
        if used.insert(name.clone()) {
            return name;
        }
        suffix += 1;
    }
}

/// Names the members of a level: snake case, unique within the level, clear
/// of the generated types' own methods and of clippy's naming conventions.
fn name_members(level: &mut Level) -> Result<(), GeneratorError> {
    let mut used: HashSet<String> = RESERVED_MEMBER_NAMES
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut idents = Vec::with_capacity(level.members.len());
    for member in &level.members {
        let (name, tag, what) = match member {
            Member::Field(field) => (field.name.as_str(), field.tag, "field"),
            Member::Group(group) => (group.name.as_str(), group.count_tag, "group"),
        };
        let mut base = to_snake_case(name);
        if !is_valid_ident(&base) {
            return Err(GeneratorError::UnnameableItem {
                what,
                name: name.to_string(),
            });
        }
        if CONVENTION_PREFIXES
            .iter()
            .any(|prefix| base.starts_with(prefix))
        {
            base = format!("field_{base}");
        }
        idents.push(to_field_ident(&unique_name(&mut used, &base, tag)));
    }
    level.idents = idents;
    Ok(())
}

/// Turns free text into PascalCase words: split on anything that is not an
/// ASCII letter or digit; an all-capital word keeps only its first capital,
/// any other word just gains one.
fn pascal_words(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for word in text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
    {
        let shout = !word.chars().any(|c| c.is_ascii_lowercase());
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
        }
        for c in chars {
            out.push(if shout { c.to_ascii_lowercase() } else { c });
        }
    }
    out
}

/// Returns true for an identifier clippy's `upper_case_acronyms` rejects:
/// longer than two characters and all capital letters.
fn is_upper_acronym(name: &str) -> bool {
    name.len() > 2 && name.chars().all(|c| c.is_ascii_uppercase())
}

/// Lowers all but the first letter of an all-capital name (`ABC` -> `Abc`).
fn soften_acronym(name: &str) -> String {
    if !is_upper_acronym(name) {
        return name.to_string();
    }
    let mut chars = name.chars();
    let mut out = String::with_capacity(name.len());
    if let Some(first) = chars.next() {
        out.push(first);
    }
    out.extend(chars.map(|c| c.to_ascii_lowercase()));
    out
}

/// Returns true when a variant name repeats its enumeration's name the way
/// `clippy::enum_variant_names` rejects: it ends with it, or starts with it
/// followed by a character that is not lowercase, unless only digits follow
/// (`Triggered1`). The lint also lets a non-lowercase character followed by
/// a digit pass; this check does not, which never costs more than a rename.
fn clashes_with_enum_name(enum_name: &str, variant: &str) -> bool {
    if variant.ends_with(enum_name) {
        return true;
    }
    variant.strip_prefix(enum_name).is_some_and(|rest| {
        rest.chars().next().is_some_and(|next| !next.is_lowercase())
            && !rest.chars().all(|c| c.is_ascii_digit())
    })
}

/// Returns true when `candidate` can name a variant of `enum_name`.
fn acceptable_variant(enum_name: &str, candidate: &str, used: &HashSet<String>) -> bool {
    is_valid_ident(candidate)
        && candidate
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase())
        && candidate != OTHER
        && !PRELUDE_VARIANTS.contains(&candidate)
        && !is_keyword(candidate)
        && !used.contains(candidate)
        && !is_upper_acronym(candidate)
        && !clashes_with_enum_name(enum_name, candidate)
}

/// Names the variants of `enum_name`, one per `(wire value, description)`,
/// deterministically in the order given.
///
/// The first acceptable candidate wins: the description in PascalCase, then
/// that followed by the wire value, then `Value` followed by the wire value,
/// then `Value`, the description and the value, and finally `Value1`,
/// `Value2`, ... (`Code1`, `Code2`, ... for an enumeration whose name starts
/// with `V`). An empty description is replaced by `Value` and the wire
/// value; one that starts with a digit is prefixed with `Value`. A candidate
/// is refused when it is not an identifier, is the fallback `Other` or a
/// variant of the prelude's `Option` / `Result` (`None`, `Some`, `Ok`,
/// `Err`), a keyword, already taken, an all-capital acronym, or repeats the
/// enumeration's name.
fn variant_names<'v>(
    enum_name: &str,
    values: impl Iterator<Item = (&'v str, &'v str)>,
) -> Vec<String> {
    let mut used: HashSet<String> = HashSet::new();
    let mut names = Vec::new();
    for (value, description) in values {
        let value_words = pascal_words(value);
        let words = pascal_words(description);
        let base = if words.is_empty() {
            format!("{VALUE_PREFIX}{value_words}")
        } else if words.starts_with(|c: char| c.is_ascii_digit()) {
            format!("{VALUE_PREFIX}{words}")
        } else {
            words
        };
        let base = soften_acronym(&base);
        let mut candidates = vec![
            base.clone(),
            format!("{base}{value_words}"),
            format!("{VALUE_PREFIX}{value_words}"),
        ];
        if !base.starts_with(VALUE_PREFIX) {
            candidates.push(format!("{VALUE_PREFIX}{base}{value_words}"));
        }
        let chosen = match candidates
            .into_iter()
            .find(|candidate| acceptable_variant(enum_name, candidate, &used))
        {
            Some(chosen) => chosen,
            None => {
                // A numbered family whose first letter differs from the
                // enumeration's, so no member can start with its name; at
                // most one member can equal it. The loop therefore ends.
                let prefix = if enum_name.starts_with('V') {
                    FALLBACK_PREFIX
                } else {
                    VALUE_PREFIX
                };
                let mut index = 1usize;
                loop {
                    let candidate = format!("{prefix}{index}");
                    if acceptable_variant(enum_name, &candidate, &used) {
                        break candidate;
                    }
                    index += 1;
                }
            }
        };
        used.insert(chosen.clone());
        names.push(chosen);
    }
    names
}

/// Makes dictionary text safe for a one-line doc comment: control
/// characters (a newline would end the comment) become spaces, and backticks
/// become quotes so the text cannot break the surrounding code spans.
fn doc_text(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            c if c.is_control() => ' ',
            '`' => '\'',
            c => c,
        })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Builds the member for a field reference, not yet paired.
fn field_member(def: &FieldDef, name: &str, required: bool) -> FieldMember {
    FieldMember {
        tag: def.tag,
        name: name.to_string(),
        required,
        kind: Kind::of(def),
        field_type: def.field_type,
        doc: field_title(def),
        pair: Pair::None,
    }
}

/// The doc title of a field: name, tag and description.
fn field_title(def: &FieldDef) -> String {
    let mut doc = format!("{} (tag {}).", doc_text(&def.name), def.tag);
    if let Some(description) = &def.description {
        let description = doc_text(description);
        if !description.is_empty() {
            doc.push(' ');
            doc.push_str(&description);
        }
    }
    doc
}

/// Renders `value` as a Rust byte-string literal.
fn byte_literal(value: &[u8]) -> String {
    let mut out = String::with_capacity(value.len() + 3);
    out.push_str("b\"");
    for &byte in value {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            0x20..=0x7e => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push('"');
    out
}

/// Generates the views file for `dict`.
pub(crate) fn generate(dict: &Dictionary, visibility: &str) -> Result<String, GeneratorError> {
    let model = build(dict)?;
    let mut code = String::new();
    line(
        &mut code,
        &format!(
            "// Generated {} views, enumerations and writers.",
            model.version
        ),
    );
    line(&mut code, "//");
    line(
        &mut code,
        "// This file was generated by ironfix-codegen. Do not edit.",
    );
    line(
        &mut code,
        &format!(
            "// It needs the ironfix-core and rust_decimal crates, and ironfix-dictionary {MIN_DICTIONARY_VERSION}"
        ),
    );
    line(
        &mut code,
        "// (it calls GroupSet::field and FieldType::is_valid_value).",
    );
    line(&mut code, "");
    emit_enums(&mut code, &model, visibility);
    emit_layouts(&mut code, &model, visibility);
    emit_views(&mut code, &model, visibility);
    emit_writers(&mut code, &model, visibility);
    Ok(code)
}

/// Emits the `enums` module.
fn emit_enums(code: &mut String, model: &Model, visibility: &str) {
    if model.enums.is_empty() {
        return;
    }
    line(
        code,
        "/// Enumerations of the fields with declared values that the views and writers use.",
    );
    line(code, "///");
    line(
        code,
        "/// An undeclared wire value stays readable: `from_bytes` maps it to `Other`, with its bytes.",
    );
    line(code, &format!("{visibility} mod enums {{"));
    if model.enums.iter().any(|model| model.multi) {
        line(
            code,
            "    /// The values of a multi-value field, one item per space-separated token.",
        );
        line(
            code,
            "    pub type Tokens<'a, E> = ::core::iter::Map<::core::slice::Split<'a, u8, fn(&u8) -> bool>, fn(&'a [u8]) -> E>;",
        );
        line(code, "");
        line(
            code,
            "    /// Returns true for the space that separates the values of a multi-value field.",
        );
        line(code, "    fn is_space(byte: &u8) -> bool {");
        line(code, "        *byte == b' '");
        line(code, "    }");
        line(code, "");
    }
    for (index, model) in model.enums.iter().enumerate() {
        if index > 0 {
            line(code, "");
        }
        emit_enum(code, model);
    }
    line(code, "}");
    line(code, "");
}

/// Emits one enumeration and its conversions.
fn emit_enum(code: &mut String, model: &EnumModel) {
    let name = &model.name;
    line(
        code,
        &format!(
            "    /// {} (tag {}): {} declared value{}.",
            doc_text(&model.field),
            model.tag,
            model.variants.len(),
            if model.variants.len() == 1 { "" } else { "s" }
        ),
    );
    line(
        code,
        "    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]",
    );
    line(code, &format!("    pub enum {name}<'a> {{"));
    for variant in &model.variants {
        let description = doc_text(&variant.description);
        if description.is_empty() {
            line(
                code,
                &format!("        /// `{}`.", doc_text(&variant.value)),
            );
        } else {
            line(
                code,
                &format!("        /// `{}`: {description}.", doc_text(&variant.value)),
            );
        }
        line(code, &format!("        {},", variant.name));
    }
    line(
        code,
        "        /// A value the dictionary does not declare, as its wire bytes.",
    );
    line(code, &format!("        {OTHER}(&'a [u8]),"));
    line(code, "    }");
    line(code, "");
    line(code, &format!("    impl<'a> {name}<'a> {{"));
    line(
        code,
        "        /// Returns the variant of a wire value; an undeclared value is `Other`.",
    );
    line(code, "        #[must_use]");
    line(
        code,
        "        pub const fn from_bytes(value: &'a [u8]) -> Self {",
    );
    line(code, "            match value {");
    for variant in &model.variants {
        line(
            code,
            &format!(
                "                {} => Self::{},",
                byte_literal(variant.value.as_bytes()),
                variant.name
            ),
        );
    }
    line(
        code,
        &format!("                other => Self::{OTHER}(other),"),
    );
    line(code, "            }");
    line(code, "        }");
    line(code, "");
    line(code, "        /// Returns the wire value.");
    line(code, "        #[must_use]");
    line(code, "        pub const fn as_bytes(&self) -> &'a [u8] {");
    line(code, "            match *self {");
    for variant in &model.variants {
        line(
            code,
            &format!(
                "                Self::{} => {},",
                variant.name,
                byte_literal(variant.value.as_bytes())
            ),
        );
    }
    line(
        code,
        &format!("                Self::{OTHER}(value) => value,"),
    );
    line(code, "            }");
    line(code, "        }");
    if model.multi {
        line(code, "");
        line(
            code,
            "        /// Splits a multi-value field into its values, one per space-separated token.",
        );
        // No `#[must_use]`: the iterator already is (`clippy::double_must_use`).
        line(
            code,
            "        pub fn tokens(value: &'a [u8]) -> Tokens<'a, Self> {",
        );
        line(
            code,
            "            value.split(is_space as fn(&u8) -> bool).map(Self::from_bytes as fn(&'a [u8]) -> Self)",
        );
        line(code, "        }");
        line(code, "");
        line(
            code,
            "        /// Joins values into a multi-value field, separated by spaces. Allocates the joined value.",
        );
        line(code, "        #[must_use]");
        line(code, "        pub fn join(values: &[Self]) -> Vec<u8> {");
        line(code, "            let mut joined = Vec::new();");
        line(
            code,
            "            for (index, value) in values.iter().enumerate() {",
        );
        line(code, "                if index > 0 {");
        line(code, "                    joined.push(b' ');");
        line(code, "                }");
        line(
            code,
            "                joined.extend_from_slice(value.as_bytes());",
        );
        line(code, "            }");
        line(code, "            joined");
        line(code, "        }");
    }
    line(code, "    }");
}

/// Emits the `layouts` module.
fn emit_layouts(code: &mut String, model: &Model, visibility: &str) {
    line(
        code,
        "/// Static repeating-group layouts for `ironfix_dictionary`'s group reader: one `GroupSpec` per",
    );
    line(
        code,
        "/// group definition and one `GroupSet` per message, checked at compile time.",
    );
    line(code, &format!("{visibility} mod layouts {{"));
    match (model.sites.is_empty(), model.messages.is_empty()) {
        (false, false) => line(code, "    use ::ironfix_dictionary::{GroupSet, GroupSpec};"),
        (false, true) => line(code, "    use ::ironfix_dictionary::GroupSpec;"),
        (true, false) => line(code, "    use ::ironfix_dictionary::GroupSet;"),
        (true, true) => {}
    }
    for site in &model.sites {
        let members = join_numbers(&site.entry.spec_members);
        let nested = site
            .entry
            .groups
            .iter()
            .filter_map(|(_, nested)| model.site(*nested))
            .map(|nested| nested.konst.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        line(code, "");
        line(
            code,
            &format!(
                "    /// {} (tag {}) group of {}; entries start with tag {}.",
                doc_text(&site.name),
                site.count_tag,
                doc_text(&site.owner_doc),
                site.delimiter_tag
            ),
        );
        line(
            code,
            &format!(
                "    pub const {}: GroupSpec<'static> = match GroupSpec::new({}, {}, &[{members}], &[{nested}]) {{",
                site.konst, site.count_tag, site.delimiter_tag
            ),
        );
        line(code, "        Ok(spec) => spec,");
        line(
            code,
            &format!(
                "        Err(_) => panic!(\"invalid {} group table\"),",
                site.base
            ),
        );
        line(code, "    };");
    }
    for message in &model.messages {
        let groups = message
            .top_groups
            .iter()
            .filter_map(|site| model.site(*site))
            .map(|site| site.konst.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        line(code, "");
        line(
            code,
            &format!(
                "    /// Groups that may open at the top level of {} (MsgType={}), header and trailer groups included.",
                doc_text(&message.name),
                doc_text(&message.msg_type)
            ),
        );
        line(
            code,
            &format!(
                "    pub const {}: GroupSet<'static> = match GroupSet::new(&[{groups}]) {{",
                message.konst
            ),
        );
        line(code, "        Ok(set) => set,");
        line(
            code,
            &format!(
                "        Err(_) => panic!(\"invalid {} group table\"),",
                message.base
            ),
        );
        line(code, "    };");
    }
    line(code, "}");
    line(code, "");
}

/// Joins numbers with `, `.
fn join_numbers(numbers: &[u32]) -> String {
    numbers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// What the views module uses, so it imports and emits nothing unused.
#[derive(Debug, Default)]
struct ViewUses {
    /// `FieldRef` is named: by a message's `get`, the `required` helper, or a
    /// conversion helper.
    field_ref: bool,
    /// A value is read through the grammar check (`text`).
    text: bool,
    /// The conversion helpers built on `text` that something calls.
    helpers: BTreeSet<&'static str>,
    required: bool,
    decimal: bool,
    enums: bool,
    groups: bool,
    entries: bool,
    layouts: bool,
}

impl ViewUses {
    fn of(model: &Model) -> Self {
        let mut uses = Self {
            entries: model.sites.iter().any(|site| site.in_body),
            layouts: model
                .messages
                .iter()
                .any(|message| !message.body.members.is_empty()),
            field_ref: model.messages.iter().any(|message| {
                message
                    .body
                    .members
                    .iter()
                    .any(|member| matches!(member, Member::Field(_)))
            }),
            ..Self::default()
        };
        for level in model.body_levels() {
            for member in &level.members {
                match member {
                    Member::Field(field) => {
                        let checked = field.kind.conversion().is_some()
                            || matches!(field.kind, Kind::Tokens(_));
                        uses.field_ref |= field.required || checked;
                        uses.text |= checked;
                        if let Some((helper, _)) = field.kind.conversion()
                            && helper != "text"
                        {
                            uses.helpers.insert(helper);
                        }
                        uses.required |= field.required;
                        uses.decimal |= field.kind == Kind::Decimal;
                        uses.enums |= field.kind.enum_tag().is_some();
                    }
                    Member::Group(_) => uses.groups = true,
                }
            }
        }
        uses
    }
}

/// The view conversion helpers built on `text`: name, Rust type, doc, and
/// the expression that converts once the grammar check has passed (`value`
/// is the checked text).
const VIEW_HELPERS: [(&str, &str, &str, &str); 5] = [
    (
        "decimal",
        "Decimal",
        "Returns the value of `field` as a decimal, exactly: a value with more digits than a `Decimal` holds is an error, never rounded.",
        "Decimal::from_str_exact(value).map_err(|_| DecodeError::InvalidFieldValue { tag: field.tag, reason: format!(\"'{value}' does not fit a decimal exactly\") })",
    ),
    (
        "int",
        "i64",
        "Returns the value of `field` as a signed integer.",
        "field.as_i64()",
    ),
    (
        "uint",
        "u64",
        "Returns the value of `field` as a non-negative integer.",
        "field.as_u64()",
    ),
    (
        "character",
        "char",
        "Returns the value of `field` as one ASCII character.",
        "field.as_char()",
    ),
    (
        "boolean",
        "bool",
        "Returns the value of `field` as a boolean (`Y` or `N`).",
        "field.as_bool()",
    ),
];

/// Emits the `views` module.
fn emit_views(code: &mut String, model: &Model, visibility: &str) {
    let uses = ViewUses::of(model);
    for text in [
        "/// Borrowed, typed views over decoded messages: nothing is copied out of the buffer.",
        "///",
        "/// A view reads a message-level field with the message's `layouts` set, so the same tag inside a",
        "/// repeating group is never taken for it; of a tag repeated at the message level it reads the first",
        "/// (the validator reports the repetition). A value is checked against its FIX type's grammar, the",
        "/// one `ironfix_dictionary::Validator` applies, before it is converted: a value that does not match",
        "/// it, or a decimal that does not fit `rust_decimal::Decimal` exactly, is",
        "/// `DecodeError::InvalidFieldValue`, never rounded or read leniently. An absent required field is",
        "/// `DecodeError::MissingRequiredField`. A group is checked whole before any entry is handed out,",
        "/// and is `Ok(None)` when absent: group presence is the validator's concern.",
        "///",
        "/// The views' own `Debug` prints no field value. `message()` and `entry()` return the decoded",
        "/// message and entry, whose `Debug` prints raw values, credentials included: do not log them.",
    ] {
        line(code, text);
    }
    line(code, &format!("{visibility} mod views {{"));
    if uses.text || uses.required {
        line(code, "    use ::ironfix_core::error::DecodeError;");
    }
    if uses.field_ref {
        line(code, "    use ::ironfix_core::field::FieldRef;");
    }
    if !model.messages.is_empty() {
        line(code, "    use ::ironfix_core::message::RawMessage;");
    }
    let mut dictionary_items: Vec<&str> = Vec::new();
    if uses.text {
        dictionary_items.push("FieldType");
    }
    if uses.groups {
        dictionary_items.push("GroupEntries");
    }
    if uses.groups || uses.entries {
        dictionary_items.push("GroupEntry");
    }
    if uses.groups {
        dictionary_items.push("GroupError");
    }
    match dictionary_items.as_slice() {
        [] => {}
        [item] => line(code, &format!("    use ::ironfix_dictionary::{item};")),
        items => line(
            code,
            &format!("    use ::ironfix_dictionary::{{{}}};", items.join(", ")),
        ),
    }
    if uses.decimal {
        line(code, "    use ::rust_decimal::Decimal;");
    }
    if uses.enums {
        line(code, "    use super::enums;");
    }
    if uses.layouts {
        line(code, "    use super::layouts;");
    }
    if uses.groups {
        line(code, "");
        line(
            code,
            "    /// The typed entries of a repeating group, in wire order.",
        );
        line(
            code,
            "    pub type Entries<'m, 'a, E> = ::core::iter::Map<GroupEntries<'m, 'a, 'static>, fn(GroupEntry<'m, 'a, 'static>) -> E>;",
        );
    }
    if uses.required {
        line(code, "");
        line(
            code,
            "    /// Returns `field`, or the missing-field error of `tag` when it is absent.",
        );
        line(
            code,
            "    fn required<'m, 'a>(field: Option<&'m FieldRef<'a>>, tag: u32) -> Result<&'m FieldRef<'a>, DecodeError> {",
        );
        line(
            code,
            "        field.ok_or(DecodeError::MissingRequiredField { tag })",
        );
        line(code, "    }");
    }
    if uses.text {
        for text in [
            "",
            "    /// Returns the text of `field`, checked against the grammar of `field_type`: the rule the",
            "    /// validator applies.",
            "    fn text<'a>(field: &FieldRef<'a>, field_type: FieldType) -> Result<&'a str, DecodeError> {",
            "        let value = field.as_str()?;",
            "        if field_type.is_valid_value(value) {",
            "            Ok(value)",
            "        } else {",
            "            Err(DecodeError::InvalidFieldValue {",
            "                tag: field.tag,",
            "                reason: format!(\"'{value}' is not a valid {field_type:?} value\"),",
            "            })",
            "        }",
            "    }",
        ] {
            line(code, text);
        }
    }
    for (name, ty, doc, body) in VIEW_HELPERS {
        if !uses.helpers.contains(name) {
            continue;
        }
        line(code, "");
        line(code, &format!("    /// {doc}"));
        line(
            code,
            &format!(
                "    fn {name}(field: &FieldRef<'_>, field_type: FieldType) -> Result<{ty}, DecodeError> {{"
            ),
        );
        if body.contains("value") {
            line(code, "        let value = text(field, field_type)?;");
        } else {
            line(code, "        text(field, field_type)?;");
        }
        line(code, &format!("        {body}"));
        line(code, "    }");
    }
    for message in &model.messages {
        emit_message_view(code, model, message);
    }
    for site in model.sites.iter().filter(|site| site.in_body) {
        emit_entry_view(code, model, site);
    }
    line(code, "}");
    line(code, "");
}

/// Emits an opaque `Debug` impl: generated types never print field values,
/// so a credential (a Logon `Password`) cannot reach a log through them.
fn emit_opaque_debug(code: &mut String, name: &str, generics: &str) {
    line(code, "");
    line(
        code,
        &format!("    impl ::core::fmt::Debug for {name}{generics} {{"),
    );
    line(
        code,
        "        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {",
    );
    line(
        code,
        &format!("            f.debug_struct(\"{name}\").finish_non_exhaustive()"),
    );
    line(code, "        }");
    line(code, "    }");
}

/// Emits the view of one message.
fn emit_message_view(code: &mut String, model: &Model, message: &MessageModel) {
    let name = format!("{}View", message.base);
    line(code, "");
    line(
        code,
        &format!(
            "    /// {} message (MsgType={}), read in place from a decoded message.",
            doc_text(&message.name),
            doc_text(&message.msg_type)
        ),
    );
    line(code, "    #[derive(Clone, Copy)]");
    line(code, &format!("    pub struct {name}<'m, 'a> {{"));
    line(code, "        msg: &'m RawMessage<'a>,");
    line(code, "    }");
    emit_opaque_debug(code, &name, "<'_, '_>");
    line(code, "");
    line(code, &format!("    impl<'m, 'a> {name}<'m, 'a> {{"));
    line(
        code,
        "        /// MsgType (tag 35) of the messages this view reads.",
    );
    line(
        code,
        &format!(
            "        pub const MSG_TYPE: &'static str = {:?};",
            message.msg_type
        ),
    );
    line(code, "");
    line(
        code,
        &format!(
            "        /// Returns a view of `msg`, or `None` when its MsgType is not `{}` ({}).",
            doc_text(&message.msg_type),
            doc_text(&message.name)
        ),
    );
    line(code, "        #[must_use]");
    line(
        code,
        "        pub fn from_message(msg: &'m RawMessage<'a>) -> Option<Self> {",
    );
    line(
        code,
        "            (msg.msg_type().as_str() == Self::MSG_TYPE).then_some(Self { msg })",
    );
    line(code, "        }");
    line(code, "");
    line(
        code,
        "        /// Returns the decoded message this view reads. Its `Debug` prints raw field values,\n        /// credentials included.",
    );
    line(code, "        #[must_use]");
    line(
        code,
        "        pub const fn message(&self) -> &'m RawMessage<'a> {",
    );
    line(code, "            self.msg");
    line(code, "        }");
    let has_fields = message
        .body
        .members
        .iter()
        .any(|member| matches!(member, Member::Field(_)));
    if has_fields {
        line(code, "");
        line(
            code,
            "        /// Returns the first field `tag` at the message level, outside every repeating group.",
        );
        line(
            code,
            "        fn get(&self, tag: u32) -> Option<&'m FieldRef<'a>> {",
        );
        line(
            code,
            &format!(
                "            layouts::{}.field(self.msg, tag)",
                message.konst
            ),
        );
        line(code, "        }");
    }
    let read = format!("layouts::{}.read(self.msg, ", message.konst);
    for (member, ident) in message.body.named() {
        emit_accessor(code, model, member, ident, "self.get", &read);
    }
    line(code, "    }");
}

/// Emits the view of one group entry.
fn emit_entry_view(code: &mut String, model: &Model, site: &Site) {
    let name = format!("{}View", site.base);
    line(code, "");
    line(
        code,
        &format!(
            "    /// One entry of the {} (tag {}) repeating group of {}, read in place.",
            doc_text(&site.name),
            site.count_tag,
            doc_text(&site.owner_doc)
        ),
    );
    line(code, "    #[derive(Clone, Copy)]");
    line(code, &format!("    pub struct {name}<'m, 'a> {{"));
    line(code, "        entry: GroupEntry<'m, 'a, 'static>,");
    line(code, "    }");
    emit_opaque_debug(code, &name, "<'_, '_>");
    line(code, "");
    line(code, &format!("    impl<'m, 'a> {name}<'m, 'a> {{"));
    line(
        code,
        &format!(
            "        /// Wraps an entry read with `layouts::{}`.",
            site.konst
        ),
    );
    line(
        code,
        "        const fn wrap(entry: GroupEntry<'m, 'a, 'static>) -> Self {",
    );
    line(code, "            Self { entry }");
    line(code, "        }");
    line(code, "");
    line(
        code,
        "        /// Returns the entry this view reads: its index and its fields in wire order. Its `Debug`\n        /// prints raw field values.",
    );
    line(code, "        #[must_use]");
    line(
        code,
        "        pub const fn entry(&self) -> GroupEntry<'m, 'a, 'static> {",
    );
    line(code, "            self.entry");
    line(code, "        }");
    for (member, ident) in site.entry.named() {
        emit_accessor(
            code,
            model,
            member,
            ident,
            "self.entry.get",
            "self.entry.group(",
        );
    }
    line(code, "    }");
}

/// Emits one accessor. `get` reads a field by tag; `read` opens a group read
/// and is completed with the count tag and `)`.
fn emit_accessor(
    code: &mut String,
    model: &Model,
    member: &Member,
    ident: &str,
    get: &str,
    read: &str,
) {
    line(code, "");
    match member {
        Member::Group(group) => {
            let Some(site) = model.site(group.site) else {
                return;
            };
            line(
                code,
                &format!(
                    "        /// {} (tag {}) repeating group: its entries in wire order, `None` when absent.",
                    doc_text(&group.name),
                    group.count_tag
                ),
            );
            line(
                code,
                &format!(
                    "        pub fn {ident}(&self) -> Result<Option<Entries<'m, 'a, {}View<'m, 'a>>>, GroupError> {{",
                    site.base
                ),
            );
            line(
                code,
                &format!(
                    "            Ok({read}{})?.map(|entries| entries.map({}View::wrap as fn(_) -> _)))",
                    group.count_tag, site.base
                ),
            );
            line(code, "        }");
        }
        Member::Field(field) => {
            let tag = field.tag;
            let doc = if field.required {
                format!("{} Required.", field.doc)
            } else {
                field.doc.clone()
            };
            let lookup = format!("{get}({tag})");
            let present = format!("required({lookup}, {tag})");
            let grammar = format!("FieldType::{:?}", field.field_type);
            let (ret, body) = match (field.kind.conversion(), field.kind) {
                (Some((convert, ty)), _) => {
                    if field.required {
                        (
                            format!("Result<{ty}, DecodeError>"),
                            format!("{convert}({present}?, {grammar})"),
                        )
                    } else {
                        (
                            format!("Result<Option<{ty}>, DecodeError>"),
                            format!(
                                "{lookup}.map(|field| {convert}(field, {grammar})).transpose()"
                            ),
                        )
                    }
                }
                (None, Kind::Enum(enum_tag)) => {
                    let enum_name = model.enum_name(enum_tag);
                    let ty = format!("enums::{enum_name}<'a>");
                    let map = format!("map(|field| enums::{enum_name}::from_bytes(field.value))");
                    infallible(field.required, &ty, &lookup, &present, &map)
                }
                (None, Kind::Tokens(enum_tag)) => {
                    // The whole value is checked first, so an empty token
                    // (a doubled or trailing space) or a multi-character
                    // value is an error, not an `Other(b"")` token.
                    let enum_name = model.enum_name(enum_tag);
                    let ty = format!("enums::Tokens<'a, enums::{enum_name}<'a>>");
                    let tokens =
                        format!("map(|value| enums::{enum_name}::tokens(value.as_bytes()))");
                    if field.required {
                        (
                            format!("Result<{ty}, DecodeError>"),
                            format!("text({present}?, {grammar}).{tokens}"),
                        )
                    } else {
                        (
                            format!("Result<Option<{ty}>, DecodeError>"),
                            format!(
                                "{lookup}.map(|field| text(field, {grammar}).{tokens}).transpose()"
                            ),
                        )
                    }
                }
                (None, _) => infallible(
                    field.required,
                    "&'a [u8]",
                    &lookup,
                    &present,
                    "map(|field| field.value)",
                ),
            };
            line(code, &format!("        /// {doc}"));
            if !ret.starts_with("Result") {
                line(code, "        #[must_use]");
            }
            line(code, &format!("        pub fn {ident}(&self) -> {ret} {{"));
            line(code, &format!("            {body}"));
            line(code, "        }");
        }
    }
}

/// Return type and body of an accessor whose value cannot fail to read.
fn infallible(
    required: bool,
    ty: &str,
    lookup: &str,
    present: &str,
    map: &str,
) -> (String, String) {
    if required {
        (
            format!("Result<{ty}, DecodeError>"),
            format!("{present}.{map}"),
        )
    } else {
        (format!("Option<{ty}>"), format!("{lookup}.{map}"))
    }
}

/// What the writers module uses, so it imports and emits nothing unused.
#[derive(Debug, Default)]
struct WriterUses {
    present: bool,
    /// Text and enumeration values: not empty, no SOH.
    text: bool,
    /// Data values: not empty.
    data: bool,
    /// Characters: printable ASCII.
    character: bool,
    /// Multi-value tokens: not empty, no space, no SOH.
    token: bool,
    display: bool,
    decimal: bool,
    enums: bool,
}

impl WriterUses {
    fn of(model: &Model) -> Self {
        let mut uses = Self::default();
        for level in model.body_levels() {
            for (member, _) in writer_members(level) {
                match member {
                    Member::Field(field) => {
                        uses.present |= writer_required(level, field);
                        uses.text |= matches!(field.kind, Kind::Str | Kind::Enum(_));
                        uses.data |= field.kind == Kind::Bytes;
                        uses.character |= field.kind == Kind::Char;
                        uses.token |= matches!(field.kind, Kind::Tokens(_));
                        uses.display |=
                            matches!(field.kind, Kind::Int | Kind::UInt | Kind::Decimal);
                        uses.decimal |= field.kind == Kind::Decimal;
                        uses.enums |= field.kind.enum_tag().is_some();
                    }
                    Member::Group(group) => {
                        uses.present |= group.required;
                        uses.display = true;
                    }
                }
            }
        }
        uses
    }
}

/// The members a writer takes, with their identifiers: every member but the
/// `Length` half of a LENGTH/DATA pair, which is derived from the data.
fn writer_members(level: &Level) -> impl Iterator<Item = (&Member, &str)> {
    level.named().filter(|(member, _)| {
        !matches!(member, Member::Field(field) if matches!(field.pair, Pair::Length(_)))
    })
}

/// Whether a writer must have this field: it is required, or it is the data
/// of a pair whose `Length` is.
fn writer_required(level: &Level, field: &FieldMember) -> bool {
    field.required
        || match field.pair {
            Pair::Data(length_tag) => level.members.iter().any(|member| {
                matches!(member, Member::Field(length) if length.tag == length_tag && length.required)
            }),
            Pair::None | Pair::Length(_) => false,
        }
}

/// The value checks a writer helper runs: name, doc, parameter type, and
/// the match arms that refuse a value (the last arm accepts).
const WRITER_CHECKS: [(&str, &str, &str, &[&str]); 4] = [
    (
        "check_text",
        "Refuses an empty value, or one carrying SOH, which would end the field early.",
        "Option<&[u8]>",
        &[
            "Some([]) => Err(invalid(tag, \"the value is empty\".to_string())),",
            "Some(value) if value.contains(&0x01) => Err(invalid(tag, \"the value contains SOH\".to_string())),",
        ],
    ),
    (
        "check_data",
        "Refuses an empty data value. It may carry SOH: it is written with its length.",
        "Option<&[u8]>",
        &["Some([]) => Err(invalid(tag, \"the value is empty\".to_string())),"],
    ),
    (
        "check_char",
        "Refuses a character that is not printable ASCII (a control character includes SOH).",
        "Option<char>",
        &[
            "Some(value) if !value.is_ascii() || value.is_ascii_control() => Err(invalid(tag, format!(\"{value:?} is not a printable ASCII character\"))),",
        ],
    ),
    (
        "check_token",
        "Refuses an empty token, or one carrying a space (the separator) or SOH.",
        "&[u8]",
        &[
            "[] => Err(invalid(tag, \"a token is empty\".to_string())),",
            "value if value.contains(&b' ') => Err(invalid(tag, \"a token contains a space\".to_string())),",
            "value if value.contains(&0x01) => Err(invalid(tag, \"a token contains SOH\".to_string())),",
        ],
    ),
];

/// Emits the `writers` module.
fn emit_writers(code: &mut String, model: &Model, visibility: &str) {
    let uses = WriterUses::of(model);
    for text in [
        "/// Typed writers of message bodies, to any [`Sink`](writers::Sink): a `FnMut(u32, &[u8])`",
        "/// closure, or a target that frames LENGTH/DATA pairs itself.",
        "///",
        "/// Fields are written in dictionary order; a repeating group as its count, then each entry with its",
        "/// delimiter first. Every value is checked before anything is written. Numbers are formatted on",
        "/// the stack; only a multi-value field allocates, to join its values.",
    ] {
        line(code, text);
    }
    line(code, &format!("{visibility} mod writers {{"));
    if model.messages.is_empty() {
        line(code, "}");
        return;
    }
    line(code, "    use ::ironfix_core::error::EncodeError;");
    if uses.decimal {
        line(code, "    use ::rust_decimal::Decimal;");
    }
    if uses.enums {
        line(code, "    use super::enums;");
    }
    emit_sink(code);
    if uses.present {
        for text in [
            "",
            "    /// Returns the missing-field error of `tag` unless the field is present.",
            "    fn present(present: bool, tag: u32) -> Result<(), EncodeError> {",
            "        if present {",
            "            Ok(())",
            "        } else {",
            "            Err(EncodeError::MissingRequiredField { tag })",
            "        }",
            "    }",
        ] {
            line(code, text);
        }
    }
    let emitted = [uses.text, uses.data, uses.character, uses.token];
    if emitted.contains(&true) {
        for text in [
            "",
            "    /// Builds the invalid-value error of `tag`.",
            "    fn invalid(tag: u32, reason: String) -> EncodeError {",
            "        EncodeError::InvalidFieldValue { tag, reason }",
            "    }",
        ] {
            line(code, text);
        }
    }
    for ((name, doc, parameter, refusals), used) in WRITER_CHECKS.into_iter().zip(emitted) {
        if !used {
            continue;
        }
        line(code, "");
        line(code, &format!("    /// {doc}"));
        line(
            code,
            &format!("    fn {name}(value: {parameter}, tag: u32) -> Result<(), EncodeError> {{"),
        );
        line(code, "        match value {");
        for refusal in refusals {
            line(code, &format!("            {refusal}"));
        }
        line(code, "            _ => Ok(()),");
        line(code, "        }");
        line(code, "    }");
    }
    if uses.display {
        emit_display_helper(code);
    }
    for message in &model.messages {
        let name = format!("{}Fields", message.base);
        let doc = format!(
            "Body of a {} message (MsgType={}), to write.",
            doc_text(&message.name),
            doc_text(&message.msg_type)
        );
        emit_writer(code, model, &name, &doc, &message.body, true);
    }
    for site in model.sites.iter().filter(|site| site.in_body) {
        let name = format!("{}Fields", site.base);
        let doc = format!(
            "One entry of the {} (tag {}) repeating group of {}, to write.",
            doc_text(&site.name),
            site.count_tag,
            doc_text(&site.owner_doc)
        );
        emit_writer(code, model, &name, &doc, &site.entry, false);
    }
    line(code, "}");
}

/// Emits the `Sink` trait, its implementation for closures, and the digit
/// formatter that implementation frames a LENGTH/DATA pair with.
fn emit_sink(code: &mut String) {
    for text in [
        "",
        "    /// Where a writer sends a body, one call per field.",
        "    ///",
        "    /// Every `FnMut(u32, &[u8])` closure is a sink; it receives a LENGTH/DATA pair as its two fields,",
        "    /// length first. A target that frames such pairs itself implements both methods; `data` has no",
        "    /// default, so an implementation cannot forget it. Over `ironfix_tagvalue::Encoder`, whose",
        "    /// `put_raw` refuses the tags of a pair, and over `ironfix_engine::OutboundMessage`:",
        "    ///",
        "    /// ```text",
        "    /// impl writers::Sink for ironfix_tagvalue::Encoder {",
        "    ///     fn field(&mut self, tag: u32, value: &[u8]) {",
        "    ///         self.put_raw(tag, value);",
        "    ///     }",
        "    ///     fn data(&mut self, length_tag: u32, data_tag: u32, value: &[u8]) {",
        "    ///         self.put_data(length_tag, data_tag, value);",
        "    ///     }",
        "    /// }",
        "    ///",
        "    /// impl writers::Sink for ironfix_engine::OutboundMessage {",
        "    ///     fn field(&mut self, tag: u32, value: &[u8]) {",
        "    ///         self.push_raw(tag, value);",
        "    ///     }",
        "    ///     fn data(&mut self, length_tag: u32, data_tag: u32, value: &[u8]) {",
        "    ///         self.push_data(length_tag, data_tag, value);",
        "    ///     }",
        "    /// }",
        "    /// ```",
        "    pub trait Sink {",
        "        /// Writes field `tag` with `value`.",
        "        ///",
        "        /// The writers have checked, before writing anything, that `value` is not empty and carries",
        "        /// no SOH, that a character is printable ASCII, and that every multi-value token is non-empty",
        "        /// with no space. A number or group count is formatted in decimal.",
        "        fn field(&mut self, tag: u32, value: &[u8]);",
        "",
        "        /// Writes a LENGTH/DATA pair: the length field, holding the size of `value` in bytes, then",
        "        /// the data field. `value` is not empty and may carry SOH.",
        "        fn data(&mut self, length_tag: u32, data_tag: u32, value: &[u8]);",
        "    }",
        "",
        "    impl<F: FnMut(u32, &[u8]) + ?Sized> Sink for F {",
        "        fn field(&mut self, tag: u32, value: &[u8]) {",
        "            self(tag, value);",
        "        }",
        "",
        "        fn data(&mut self, length_tag: u32, data_tag: u32, value: &[u8]) {",
        "            let mut digits = [0; 20];",
        "            self(length_tag, decimal(value.len(), &mut digits));",
        "            self(data_tag, value);",
        "        }",
        "    }",
        "",
        "    /// Writes `value` in decimal at the end of `digits` and returns the digits.",
        "    fn decimal(value: usize, digits: &mut [u8; 20]) -> &[u8] {",
        "        let mut rest = value;",
        "        let mut start = digits.len();",
        "        while let Some(index) = start.checked_sub(1) {",
        "            if let Some(slot) = digits.get_mut(index) {",
        "                *slot = b\"0123456789\".get(rest % 10).copied().unwrap_or(b'0');",
        "            }",
        "            start = index;",
        "            rest /= 10;",
        "            if rest == 0 {",
        "                break;",
        "            }",
        "        }",
        "        digits.get(start..).unwrap_or(&[])",
        "    }",
    ] {
        line(code, text);
    }
}

/// Emits the stack-buffer number formatter of the writers.
fn emit_display_helper(code: &mut String) {
    line(code, "");
    line(
        code,
        &format!(
            "    /// A {FORMAT_BUFFER_BYTES}-byte stack buffer the writers format numbers into."
        ),
    );
    line(code, "    struct Buffer {");
    line(
        code,
        &format!("        bytes: [u8; {FORMAT_BUFFER_BYTES}],"),
    );
    line(code, "        len: usize,");
    line(code, "    }");
    line(code, "");
    line(code, "    impl ::core::fmt::Write for Buffer {");
    line(
        code,
        "        fn write_str(&mut self, text: &str) -> ::core::fmt::Result {",
    );
    line(
        code,
        "            let end = self.len.checked_add(text.len()).ok_or(::core::fmt::Error)?;",
    );
    line(
        code,
        "            let slot = self.bytes.get_mut(self.len..end).ok_or(::core::fmt::Error)?;",
    );
    line(code, "            slot.copy_from_slice(text.as_bytes());");
    line(code, "            self.len = end;");
    line(code, "            Ok(())");
    line(code, "        }");
    line(code, "    }");
    line(code, "");
    line(
        code,
        "    /// Formats `value` on the stack and writes it as field `tag`.",
    );
    line(
        code,
        "    fn put_display<S: Sink + ?Sized, T: ::core::fmt::Display>(sink: &mut S, tag: u32, value: T) -> Result<(), EncodeError> {",
    );
    line(
        code,
        &format!(
            "        let mut buffer = Buffer {{ bytes: [0; {FORMAT_BUFFER_BYTES}], len: 0 }};"
        ),
    );
    line(
        code,
        "        let written = ::core::fmt::Write::write_fmt(&mut buffer, format_args!(\"{value}\"));",
    );
    line(
        code,
        "        match (written, buffer.bytes.get(..buffer.len)) {",
    );
    line(code, "            (Ok(()), Some(bytes)) => {");
    line(code, "                sink.field(tag, bytes);");
    line(code, "                Ok(())");
    line(code, "            }");
    line(
        code,
        "            _ => Err(EncodeError::InvalidFieldValue {",
    );
    line(code, "                tag,");
    line(
        code,
        &format!(
            "                reason: \"the value does not fit the {FORMAT_BUFFER_BYTES}-byte formatting buffer\".to_string(),"
        ),
    );
    line(code, "            }),");
    line(code, "        }");
    line(code, "    }");
}

/// Whether the writer struct of a level borrows (and so needs a lifetime).
fn writer_borrows(level: &Level) -> bool {
    writer_members(level).any(|(member, _)| match member {
        Member::Field(field) => field.kind.borrows(),
        Member::Group(_) => true,
    })
}

/// The Rust type of a writer field.
fn writer_type(model: &Model, member: &Member) -> String {
    match member {
        Member::Group(group) => {
            let (base, borrows) = model.site(group.site).map_or(("", false), |site| {
                (site.base.as_str(), writer_borrows(&site.entry))
            });
            if borrows {
                format!("&'v [{base}Fields<'v>]")
            } else {
                format!("&'v [{base}Fields]")
            }
        }
        Member::Field(field) => match field.kind {
            Kind::Str => "Option<&'v str>".to_string(),
            Kind::Bytes => "Option<&'v [u8]>".to_string(),
            Kind::Char => "Option<char>".to_string(),
            Kind::Bool => "Option<bool>".to_string(),
            Kind::Int => "Option<i64>".to_string(),
            Kind::UInt => "Option<u64>".to_string(),
            Kind::Decimal => "Option<Decimal>".to_string(),
            Kind::Enum(tag) => format!("Option<enums::{}<'v>>", model.enum_name(tag)),
            Kind::Tokens(tag) => format!("&'v [enums::{}<'v>]", model.enum_name(tag)),
        },
    }
}

/// The statements that check a writer before it writes.
fn writer_checks(level: &Level) -> Vec<String> {
    let mut checks = Vec::new();
    for (member, ident) in writer_members(level) {
        match member {
            Member::Field(field) => {
                if writer_required(level, field) {
                    let present = match field.kind {
                        Kind::Tokens(_) => format!("!self.{ident}.is_empty()"),
                        _ => format!("self.{ident}.is_some()"),
                    };
                    checks.push(format!("present({present}, {})?;", field.tag));
                }
                let tag = field.tag;
                match field.kind {
                    Kind::Str => checks.push(format!(
                        "check_text(self.{ident}.map(str::as_bytes), {tag})?;"
                    )),
                    Kind::Enum(_) => checks.push(format!(
                        "check_text(self.{ident}.map(|value| value.as_bytes()), {tag})?;"
                    )),
                    Kind::Bytes => checks.push(format!("check_data(self.{ident}, {tag})?;")),
                    Kind::Char => checks.push(format!("check_char(self.{ident}, {tag})?;")),
                    Kind::Tokens(_) => {
                        checks.push(format!("for value in self.{ident} {{"));
                        checks.push(format!("    check_token(value.as_bytes(), {tag})?;"));
                        checks.push("}".to_string());
                    }
                    Kind::Bool | Kind::Int | Kind::UInt | Kind::Decimal => {}
                }
            }
            Member::Group(group) => {
                if group.required {
                    checks.push(format!(
                        "present(!self.{ident}.is_empty(), {})?;",
                        group.count_tag
                    ));
                }
                checks.push(format!("for entry in self.{ident} {{"));
                checks.push("    entry.check()?;".to_string());
                checks.push("}".to_string());
            }
        }
    }
    checks
}

/// The statements that write a level, in member order.
fn writer_emits(model: &Model, level: &Level) -> Vec<String> {
    let mut emits = Vec::new();
    for (member, ident) in writer_members(level) {
        match member {
            Member::Field(field) => {
                let tag = field.tag;
                let statement = match (field.kind, field.pair) {
                    (Kind::Bytes, Pair::Data(length_tag)) => format!(
                        "if let Some(value) = self.{ident} {{ sink.data({length_tag}, {tag}, value); }}"
                    ),
                    (Kind::Str | Kind::Enum(_), _) => format!(
                        "if let Some(value) = self.{ident} {{ sink.field({tag}, value.as_bytes()); }}"
                    ),
                    (Kind::Bytes, _) => {
                        format!("if let Some(value) = self.{ident} {{ sink.field({tag}, value); }}")
                    }
                    (Kind::Char, _) => format!(
                        "if let Some(value) = self.{ident} {{ sink.field({tag}, value.encode_utf8(&mut [0; 4]).as_bytes()); }}"
                    ),
                    (Kind::Bool, _) => format!(
                        "if let Some(value) = self.{ident} {{ sink.field({tag}, if value {{ b\"Y\" }} else {{ b\"N\" }}); }}"
                    ),
                    (Kind::Int | Kind::UInt | Kind::Decimal, _) => format!(
                        "if let Some(value) = self.{ident} {{ put_display(sink, {tag}, value)?; }}"
                    ),
                    (Kind::Tokens(enum_tag), _) => format!(
                        "if !self.{ident}.is_empty() {{ sink.field({tag}, &enums::{}::join(self.{ident})); }}",
                        model.enum_name(enum_tag)
                    ),
                };
                emits.push(statement);
            }
            Member::Group(group) => {
                emits.push(format!("if !self.{ident}.is_empty() {{"));
                emits.push(format!(
                    "    put_display(sink, {}, self.{ident}.len())?;",
                    group.count_tag
                ));
                emits.push(format!("    for entry in self.{ident} {{"));
                emits.push("        entry.emit(sink)?;".to_string());
                emits.push("    }".to_string());
                emits.push("}".to_string());
            }
        }
    }
    emits
}

/// The doc line of a writer field.
fn writer_field_doc(level: &Level, member: &Member) -> String {
    match member {
        Member::Field(field) => {
            let mut doc = field.doc.clone();
            if writer_required(level, field) {
                doc.push_str(" Required.");
            }
            if let Pair::Data(length_tag) = field.pair {
                doc.push_str(&format!(
                    " Written with its length (tag {length_tag}), which is derived from it."
                ));
            }
            if matches!(field.kind, Kind::Tokens(_)) {
                doc.push_str(" Empty when absent.");
            }
            doc
        }
        Member::Group(group) => {
            let mut doc = format!(
                "{} (tag {}) repeating group: one item per entry, empty when absent.",
                doc_text(&group.name),
                group.count_tag
            );
            if group.required {
                doc.push_str(" Required.");
            }
            doc
        }
    }
}

/// Emits one writer struct and its methods. A message writer gets a public
/// `write`; an entry writer only the `check` and `emit` its message calls.
fn emit_writer(
    code: &mut String,
    model: &Model,
    name: &str,
    doc: &str,
    level: &Level,
    top_level: bool,
) {
    let (declared, anonymous) = if writer_borrows(level) {
        ("<'v>", "<'_>")
    } else {
        ("", "")
    };
    line(code, "");
    line(code, &format!("    /// {doc}"));
    line(code, "    #[derive(Clone, Copy, Default)]");
    if writer_members(level).next().is_none() {
        line(code, &format!("    pub struct {name} {{}}"));
    } else {
        line(code, &format!("    pub struct {name}{declared} {{"));
        for (member, ident) in writer_members(level) {
            line(
                code,
                &format!("        /// {}", writer_field_doc(level, member)),
            );
            line(
                code,
                &format!("        pub {ident}: {},", writer_type(model, member)),
            );
        }
        line(code, "    }");
    }
    emit_opaque_debug(code, name, anonymous);
    line(code, "");
    line(code, &format!("    impl {name}{anonymous} {{"));
    let checks = writer_checks(level);
    let emits = writer_emits(model, level);
    if top_level {
        for text in [
            "        /// Writes the body to `sink`, one call per field, in dictionary order: a repeating group",
            "        /// as its count, then each entry with its delimiter first.",
            "        ///",
            "        /// # Errors",
            "        /// `EncodeError::MissingRequiredField` for an absent required field or group, or an entry",
            "        /// without its delimiter; `EncodeError::InvalidFieldValue` for an empty value, SOH in a",
            "        /// value other than data, a `char` that is not printable ASCII, or a multi-value token",
            "        /// that is empty or carries a space. All are checked before anything is written.",
        ] {
            line(code, text);
        }
        if emits.is_empty() {
            line(
                code,
                "        pub fn write<S: Sink + ?Sized>(&self, _sink: &mut S) -> Result<(), EncodeError> {",
            );
            line(code, "            Ok(())");
        } else {
            line(
                code,
                "        pub fn write<S: Sink + ?Sized>(&self, sink: &mut S) -> Result<(), EncodeError> {",
            );
            if !checks.is_empty() {
                line(code, "            self.check()?;");
            }
            line(code, "            self.emit(sink)");
        }
        line(code, "        }");
    }
    if !checks.is_empty() {
        if top_level {
            line(code, "");
        }
        line(
            code,
            "        /// Checks required fields, groups and entries before anything is written.",
        );
        line(code, "        fn check(&self) -> Result<(), EncodeError> {");
        for statement in &checks {
            line(code, &format!("            {statement}"));
        }
        line(code, "            Ok(())");
        line(code, "        }");
    }
    if !emits.is_empty() {
        line(code, "");
        line(code, "        /// Writes the fields, in dictionary order.");
        line(
            code,
            "        fn emit<S: Sink + ?Sized>(&self, sink: &mut S) -> Result<(), EncodeError> {",
        );
        for statement in &emits {
            line(code, &format!("            {statement}"));
        }
        line(code, "            Ok(())");
        line(code, "        }");
    }
    line(code, "    }");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pascal_words_splits_on_punctuation_and_softens_capitals() {
        assert_eq!(pascal_words("PARTIALLY_FILLED"), "PartiallyFilled");
        assert_eq!(pascal_words("EUC-JP"), "EucJp");
        assert_eq!(pascal_words("ISO Country Code"), "IsoCountryCode");
        assert_eq!(pascal_words("kW-a"), "KWA");
        assert_eq!(pascal_words("1_DAY"), "1Day");
        assert_eq!(pascal_words("?"), "");
        assert_eq!(pascal_words(""), "");
    }

    #[test]
    fn test_clashes_with_enum_name_follows_enum_variant_names() {
        // Ends with the enumeration's name.
        assert!(clashes_with_enum_name("SecurityType", "NoSecurityType"));
        assert!(clashes_with_enum_name("Triggered", "Triggered"));
        // Starts with it, then a capital.
        assert!(clashes_with_enum_name("Side", "SideBuy"));
        // Starts with it inside a word: not the enumeration's name.
        assert!(!clashes_with_enum_name("Side", "Sidecar"));
        assert!(!clashes_with_enum_name("Side", "Buy"));
        // Only digits after the name: the lint lets it pass.
        assert!(!clashes_with_enum_name("Triggered", "Triggered1"));
        assert!(clashes_with_enum_name("Triggered", "Triggered1A"));
    }

    /// Names variants for `(value, description)` pairs.
    fn names(enum_name: &str, pairs: &[(&str, &str)]) -> Vec<String> {
        variant_names(enum_name, pairs.iter().copied())
    }

    #[test]
    fn test_variant_names_use_the_description() {
        assert_eq!(
            names("Side", &[("1", "BUY"), ("2", "SELL")]),
            vec!["Buy", "Sell"]
        );
    }

    #[test]
    fn test_variant_names_never_take_the_fallback_name() {
        assert_eq!(
            names("PartyIDSource", &[("1", "KOREAN"), ("99", "OTHER")]),
            vec!["Korean", "Other99"]
        );
    }

    #[test]
    fn test_variant_names_disambiguate_collisions_with_the_value() {
        // FIX 5.0 SP2 BenchmarkCurveName declares EURIBOR and Euribor.
        assert_eq!(
            names(
                "BenchmarkCurveName",
                &[("EURIBOR", "EURIBOR"), ("Euribor", "EURIBOR")]
            ),
            vec!["Euribor", "EuriborEuribor"]
        );
    }

    #[test]
    fn test_variant_names_handle_keywords_empty_and_digit_descriptions() {
        assert_eq!(
            names(
                "Mode",
                &[("S", "SELF"), ("E", ""), ("D", "1_DAY"), ("?", "")]
            ),
            vec!["SelfS", "ValueE", "Value1Day", "Value"]
        );
    }

    #[test]
    fn test_variant_names_avoid_the_enumeration_name_and_acronyms() {
        // FIX 4.4 SecurityType declares NO_SECURITY_TYPE.
        assert_eq!(
            names(
                "SecurityType",
                &[("NONE", "NO_SECURITY_TYPE"), ("Q", "SECURITY_TYPE_XY")]
            ),
            vec!["NoSecurityTypeNone", "ValueQ"]
        );
        // Single letters would join into an all-capital acronym.
        assert_eq!(names("Flag", &[("1", "A_B_C")]), vec!["Abc"]);
    }

    #[test]
    fn test_variant_names_fall_back_to_numbered_values() {
        // Every meaningful candidate is taken or refused.
        assert_eq!(
            names("Value", &[("", ""), ("", "")]),
            vec!["Code1", "Code2"]
        );
        assert_eq!(
            names("Mode", &[("", ""), ("", "")]),
            vec!["Value", "Value1"]
        );
    }

    #[test]
    fn test_byte_literal_escapes_quotes_backslashes_and_non_ascii() {
        assert_eq!(byte_literal(b"1"), "b\"1\"");
        assert_eq!(byte_literal(b"a\"b\\c"), "b\"a\\\"b\\\\c\"");
        assert_eq!(byte_literal("é".as_bytes()), "b\"\\xc3\\xa9\"");
        assert_eq!(byte_literal(b"\x01"), "b\"\\x01\"");
    }

    #[test]
    fn test_doc_text_cannot_end_the_comment() {
        assert_eq!(doc_text("line\nbreak\r`x`"), "line break 'x'");
    }

    #[test]
    fn test_soften_acronym_only_touches_all_capitals() {
        assert_eq!(soften_acronym("IOI"), "Ioi");
        assert_eq!(soften_acronym("IOIID"), "Ioiid");
        assert_eq!(soften_acronym("ClOrdID"), "ClOrdID");
        assert_eq!(soften_acronym("AB"), "AB");
    }

    #[test]
    fn test_name_members_avoids_reserved_and_convention_names() {
        let mut level = Level {
            members: vec![
                Member::Field(FieldMember {
                    tag: 1,
                    name: "Get".to_string(),
                    required: false,
                    kind: Kind::Str,
                    doc: String::new(),
                    pair: Pair::None,
                    field_type: FieldType::String,
                }),
                Member::Field(FieldMember {
                    tag: 2,
                    name: "ToDate".to_string(),
                    required: false,
                    kind: Kind::Str,
                    doc: String::new(),
                    pair: Pair::None,
                    field_type: FieldType::String,
                }),
                Member::Field(FieldMember {
                    tag: 3,
                    name: "Yield".to_string(),
                    required: false,
                    kind: Kind::Decimal,
                    doc: String::new(),
                    pair: Pair::None,
                    field_type: FieldType::String,
                }),
            ],
            ..Level::default()
        };
        assert!(name_members(&mut level).is_ok());
        assert_eq!(level.idents, vec!["get_1", "field_to_date", "r#yield"]);
    }

    use crate::CodeGenerator;
    use crate::generator::GeneratorConfig;
    use ironfix_dictionary::schema::Member as SchemaMember;
    use ironfix_dictionary::schema::{ComponentDef, MessageCategory, Version};

    /// Generates views, failing the test with the generator error.
    #[track_caller]
    fn views(dict: &Dictionary) -> String {
        match CodeGenerator::new().generate_views(dict) {
            Ok(code) => code,
            Err(err) => panic!("views must generate: {err}"),
        }
    }

    /// Loads an embedded dictionary, failing the test with the load error.
    #[track_caller]
    fn embedded(
        loaded: Result<&'static Dictionary, ironfix_dictionary::DictionaryError>,
    ) -> &'static Dictionary {
        match loaded {
            Ok(dict) => dict,
            Err(err) => panic!("the embedded dictionary must load: {err}"),
        }
    }

    /// Asserts the properties every views file must have.
    #[track_caller]
    fn assert_lint_clean_shape(code: &str) {
        assert!(!code.contains("#[allow"), "no #[allow] in generated text");
        // Token-wise: `YieldValueOf32nds` (FIX 5.0 SP2) is a variant name.
        assert!(
            !code
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|token| token == "f64" || token == "f32"),
            "no binary floating point type"
        );
        assert!(!code.contains("//!"), "the file must stay include!-able");
        assert!(!code.contains("todo!") && !code.contains("unimplemented!"));
        assert!(!code.contains("unsafe"));
    }

    #[test]
    fn test_generate_views_for_every_embedded_dictionary() {
        // FIX 4.4 views are about 4.2 MB and FIX 5.0 SP2 views about 26 MB:
        // generated and inspected here, compiled out of tree (see ADR-0012).
        for dict in [
            embedded(Dictionary::fix44()),
            embedded(Dictionary::fix42()),
            embedded(Dictionary::fixt11()),
            embedded(Dictionary::fix50sp2()),
        ] {
            let code = views(dict);
            assert_lint_clean_shape(&code);
            assert_eq!(code, views(dict), "generation is deterministic");
            assert!(code.starts_with(&format!(
                "// Generated {} views, enumerations and writers.",
                dict.version
            )));
        }
        let fix44 = views(embedded(Dictionary::fix44()));
        assert!(fix44.contains("pub struct NewOrderSingleView<'m, 'a> {"));
        assert!(fix44.contains("pub struct NewOrderSingleFields<'v> {"));
        assert!(fix44.contains("pub fn price(&self) -> Result<Option<Decimal>, DecodeError> {"));
        assert!(fix44.contains("pub price: Option<Decimal>,"));
        // One view per group definition: Parties is used by many messages.
        assert_eq!(
            fix44
                .matches("pub struct PartiesNoPartyIDsView<'m, 'a> {")
                .count(),
            1
        );
        // FIX 5.0 SP2 Triggered(1827) declares NOT_TRIGGERED, TRIGGERED and
        // *_TRIGGERED values: renamed off the enumeration's name.
        let fix50sp2 = views(embedded(Dictionary::fix50sp2()));
        assert!(fix50sp2.contains("        NotTriggered0,"));
        assert!(fix50sp2.contains("        Triggered1,"));
        // NoPaymentStreamFormulas(42683) entries open with the length of
        // PaymentStreamFormula: the pair is kept and written first.
        assert!(fix50sp2.contains("            if let Some(value) = self.payment_stream_formula { sink.data(43109, 42684, value); }"));
        // FIX 4.4 EncryptMethod `NONE` would shadow `Option::None`.
        assert!(fix44.contains("        None0,"));
    }

    #[test]
    fn test_generate_views_does_not_change_the_default_output() {
        let generator = CodeGenerator::new();
        let dict = embedded(Dictionary::fix44());
        let before = generator.generate(dict);
        let _ = generator.generate_views(dict);
        assert_eq!(generator.generate(dict), before);
        let default = match before {
            Ok(code) => code,
            Err(err) => panic!("default output must generate: {err}"),
        };
        assert!(!default.contains("mod views"));
        assert!(!default.contains("mod writers"));
    }

    #[test]
    fn test_generate_views_respects_configured_visibility() {
        let generator = CodeGenerator::with_config(GeneratorConfig {
            visibility: "pub(crate)".to_string(),
            ..GeneratorConfig::default()
        });
        let code = match generator.generate_views(embedded(Dictionary::fixt11())) {
            Ok(code) => code,
            Err(err) => panic!("views must generate: {err}"),
        };
        for module in ["enums", "layouts", "views", "writers"] {
            assert!(
                code.contains(&format!("pub(crate) mod {module} {{")),
                "{module}"
            );
        }
    }

    /// A dictionary with one message `D` built from the given parts.
    fn dict_with(
        fields: Vec<SchemaFieldRef>,
        groups: Vec<GroupDef>,
        components: Vec<ComponentRef>,
    ) -> Dictionary {
        let mut dict = Dictionary::new(Version::Fix44);
        for (tag, name, field_type) in [
            (11u32, "ClOrdID", FieldType::String),
            (78, "NoAllocs", FieldType::NumInGroup),
            (79, "AllocAccount", FieldType::String),
            (95, "RawDataLength", FieldType::Length),
            (96, "RawData", FieldType::Data),
        ] {
            dict.add_field(FieldDef::new(tag, name, field_type));
        }
        dict.add_message(MessageDef::new(
            "D",
            "NewOrderSingle",
            MessageCategory::App,
            fields
                .into_iter()
                .map(SchemaMember::Field)
                .chain(groups.into_iter().map(SchemaMember::Group))
                .chain(components.into_iter().map(SchemaMember::Component)),
        ));
        dict
    }

    fn reference(tag: u32, name: &str, required: bool) -> SchemaFieldRef {
        SchemaFieldRef {
            tag,
            name: name.to_string(),
            required,
        }
    }

    fn allocs(required: bool, delimiter_tag: u32) -> GroupDef {
        GroupDef::new(
            78,
            "NoAllocs",
            delimiter_tag,
            required,
            [SchemaMember::Field(reference(79, "AllocAccount", false))],
        )
    }

    #[test]
    fn test_generate_views_checks_a_required_group_and_its_delimiter() {
        let code = views(&dict_with(Vec::new(), vec![allocs(true, 79)], Vec::new()));
        assert!(code.contains("present(!self.no_allocs.is_empty(), 78)?;"));
        // The delimiter opens every entry, so its writer requires it even
        // though the dictionary marks it optional.
        assert!(code.contains("present(self.alloc_account.is_some(), 79)?;"));
        assert!(code.contains("pub fn alloc_account(&self) -> Result<&'a str, DecodeError> {"));
    }

    #[test]
    fn test_generate_views_pairs_a_length_with_the_data_after_it() {
        let code = views(&dict_with(
            vec![
                reference(95, "RawDataLength", false),
                reference(96, "RawData", true),
            ],
            Vec::new(),
            Vec::new(),
        ));
        // The writer derives the length from the data.
        assert!(code.contains("sink.data(95, 96, value);"));
        assert!(!code.contains("pub raw_data_length:"));
        // The view reads both.
        assert!(code.contains("pub fn raw_data_length(&self)"));
        assert!(code.contains("pub fn raw_data(&self) -> Result<&'a [u8], DecodeError> {"));
    }

    /// A NoAllocs group with the given delimiter and fields.
    fn allocs_with(delimiter_tag: u32, fields: Vec<SchemaFieldRef>) -> GroupDef {
        GroupDef::new(
            78,
            "NoAllocs",
            delimiter_tag,
            false,
            fields.into_iter().map(SchemaMember::Field),
        )
    }

    #[test]
    fn test_generate_views_keeps_a_pair_whose_length_is_the_delimiter() {
        // FIX 5.0 SP2 NoPaymentStreamFormulas entries open with
        // PaymentStreamFormulaLength: the pair is kept and written first.
        let group = allocs_with(
            95,
            vec![
                reference(95, "RawDataLength", false),
                reference(96, "RawData", false),
                reference(79, "AllocAccount", false),
            ],
        );
        let code = views(&dict_with(Vec::new(), vec![group], Vec::new()));
        let Some(start) = code.find("impl NewOrderSingleNoAllocsFields<'_> {") else {
            panic!("the entry writer must be generated: {code}");
        };
        let entry = code.get(start..).unwrap_or_default();
        assert!(entry.contains("present(self.raw_data.is_some(), 96)?;"));
        let pair = entry.find("sink.data(95, 96, value);");
        let account = entry.find("sink.field(79, value.as_bytes());");
        assert!(pair.is_some() && pair < account, "the pair opens the entry");
        // The view reads the delimiter and requires the data.
        assert!(code.contains("pub fn raw_data_length(&self) -> Result<u64, DecodeError> {"));
        assert!(code.contains("pub fn raw_data(&self) -> Result<&'a [u8], DecodeError> {"));
        assert!(!code.contains("pub raw_data_length:"));
    }

    #[test]
    fn test_generate_views_unpaired_data_field_is_a_typed_error() {
        for fields in [
            vec![reference(96, "RawData", true)],
            vec![
                reference(11, "ClOrdID", true),
                reference(96, "RawData", true),
            ],
        ] {
            assert_eq!(
                CodeGenerator::new().generate_views(&dict_with(fields, Vec::new(), Vec::new())),
                Err(GeneratorError::UnpairedDataField {
                    tag: 96,
                    scope: "message NewOrderSingle".to_string(),
                })
            );
        }
        // A data field opening a group entry: its length would have to come
        // before the delimiter.
        let group = allocs_with(
            96,
            vec![
                reference(95, "RawDataLength", false),
                reference(96, "RawData", false),
            ],
        );
        assert_eq!(
            CodeGenerator::new().generate_views(&dict_with(Vec::new(), vec![group], Vec::new())),
            Err(GeneratorError::UnpairedDataField {
                tag: 96,
                scope: "group NoAllocs of message NewOrderSingle".to_string(),
            })
        );
    }

    #[test]
    fn test_variant_names_never_take_prelude_variants() {
        assert_eq!(
            names(
                "EncryptMethod",
                &[("0", "NONE"), ("1", "SOME"), ("2", "OK"), ("3", "ERR")]
            ),
            vec!["None0", "Some1", "Ok2", "Err3"]
        );
    }

    #[test]
    fn test_generate_views_unknown_delimiter_field_is_a_typed_error() {
        let dict = dict_with(Vec::new(), vec![allocs(false, 9999)], Vec::new());
        assert!(matches!(
            CodeGenerator::new().generate_views(&dict),
            Err(GeneratorError::UnknownField { tag: 9999, .. })
        ));
    }

    #[test]
    fn test_generate_views_unknown_references_are_typed_errors() {
        let dict = dict_with(
            vec![reference(4242, "Mystery", true)],
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(
            CodeGenerator::new().generate_views(&dict),
            Err(GeneratorError::UnknownField {
                tag: 4242,
                scope: "message NewOrderSingle".to_string(),
            })
        );
        let dict = dict_with(
            Vec::new(),
            Vec::new(),
            vec![ComponentRef::new("Nowhere", true)],
        );
        assert_eq!(
            CodeGenerator::new().generate_views(&dict),
            Err(GeneratorError::UnknownComponent {
                name: "Nowhere".to_string(),
                scope: "message NewOrderSingle".to_string(),
            })
        );
    }

    #[test]
    fn test_generate_views_component_cycles_are_typed_errors() {
        // Directly self-referencing.
        let mut dict = dict_with(
            Vec::new(),
            Vec::new(),
            vec![ComponentRef::new("Looper", false)],
        );
        dict.add_component(ComponentDef::new(
            "Looper".to_string(),
            vec![SchemaMember::Component(ComponentRef::new("Looper", false))],
        ));
        assert_eq!(
            CodeGenerator::new().generate_views(&dict),
            Err(GeneratorError::ComponentCycle {
                name: "Looper".to_string(),
                path: "Looper -> Looper".to_string(),
            })
        );

        // Closing through a group: component -> group -> component.
        let mut dict = dict_with(
            Vec::new(),
            Vec::new(),
            vec![ComponentRef::new("Allocs", false)],
        );
        let mut group = allocs(false, 79);
        group.components = vec![ComponentRef::new("Allocs", false)];
        dict.add_component(ComponentDef::new(
            "Allocs".to_string(),
            vec![SchemaMember::Group(group)],
        ));
        assert_eq!(
            CodeGenerator::new().generate_views(&dict),
            Err(GeneratorError::ComponentCycle {
                name: "Allocs".to_string(),
                path: "Allocs -> Allocs".to_string(),
            })
        );
    }

    #[test]
    fn test_generate_views_acyclic_chain_past_the_ceiling_is_a_typed_error() {
        let length = MAX_NESTING_DEPTH + 10;
        let mut dict = dict_with(
            Vec::new(),
            Vec::new(),
            vec![ComponentRef::new("Comp0", false)],
        );
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
        assert!(matches!(
            CodeGenerator::new().generate_views(&dict),
            Err(GeneratorError::MaxDepthExceeded {
                limit: MAX_NESTING_DEPTH,
                ..
            })
        ));
    }

    #[test]
    fn test_generate_views_unnameable_component_is_a_typed_error() {
        let mut dict = dict_with(
            Vec::new(),
            Vec::new(),
            vec![ComponentRef::new("Bad-Name", false)],
        );
        dict.add_component(ComponentDef::new("Bad-Name".to_string(), Vec::new()));
        assert_eq!(
            CodeGenerator::new().generate_views(&dict),
            Err(GeneratorError::UnnameableItem {
                what: "component",
                name: "Bad-Name".to_string(),
            })
        );
    }

    #[test]
    fn test_generate_views_of_an_empty_dictionary_is_valid() {
        let code = views(&Dictionary::new(Version::Fix44));
        assert_lint_clean_shape(&code);
        assert!(!code.contains("mod enums"));
        assert!(!code.contains("use "));
    }
}
