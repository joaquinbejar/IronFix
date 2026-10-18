/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Schema expansion shared by the validator and the group reader.
//!
//! [`ScopeBuilder`] expands one [`MessageDef`] into a tree of [`Level`]s:
//! the message level (header, body and trailer merged), and below it one
//! [`LayoutGroup`] per repeating group with the level formed by one of its
//! entries. Components are flattened into the level that references them, so
//! a group is found by its count tag wherever a component placed it.
//!
//! Every list in the tree is sorted once, when its level is finished, so the
//! walks in [`crate::walk`] answer "may this tag appear here" and "does a
//! group open at this tag" by binary search, without hashing or allocating.
//!
//! The expansion is bounded by [`MAX_SCOPE_DEPTH`] and [`MAX_SCOPE_NODES`]:
//! a [`Dictionary`] built by hand or deserialised from an untrusted document
//! need not be the bounded DAG the loader produces.

use crate::schema::{ComponentRef, Dictionary, GroupDef, MessageDef};
use crate::validator::{MAX_SCOPE_DEPTH, MAX_SCOPE_NODES, ValidationError};
use std::collections::HashSet;

/// One structural level of a message: the message itself, or the members of
/// a single repeating-group entry.
#[derive(Debug, Clone, Default)]
pub(crate) struct Level {
    /// Tags that may appear at this level, group count tags included. Sorted
    /// and unique once the level is finished.
    pub(crate) members: Vec<u32>,
    /// Tags that must appear at this level, with their field names, in
    /// schema order.
    pub(crate) required: Vec<(u32, String)>,
    /// Groups that may open at this level. Sorted by count tag and unique
    /// once the level is finished; the first expansion of a count tag wins.
    pub(crate) groups: Vec<LayoutGroup>,
    /// The count tags of `groups`, in the same order: a dense array to search
    /// instead of the groups themselves.
    pub(crate) group_tags: Vec<u32>,
}

impl Level {
    fn add_field(&mut self, tag: u32, name: &str, required: bool) {
        self.members.push(tag);
        if required {
            self.required.push((tag, name.to_string()));
        }
    }

    /// Sorts the member and group lists so they can be searched.
    ///
    /// The sort is stable, so of two groups sharing a count tag at one level
    /// (a schema defect, not something to resolve here) the one expanded
    /// first is kept.
    fn finish(&mut self) {
        self.members.sort_unstable();
        self.members.dedup();
        self.groups.sort_by_key(|group| group.count_tag);
        self.groups.dedup_by_key(|group| group.count_tag);
        self.group_tags = self.groups.iter().map(|group| group.count_tag).collect();
    }

    /// Returns true if `tag` may appear at this level.
    pub(crate) fn allows(&self, tag: u32) -> bool {
        self.members.binary_search(&tag).is_ok()
    }

    /// Returns the group whose count field is `count_tag`, if one may open at
    /// this level.
    pub(crate) fn group(&self, count_tag: u32) -> Option<&LayoutGroup> {
        self.group_tags
            .binary_search(&count_tag)
            .ok()
            .and_then(|index| self.groups.get(index))
    }

    /// Returns every tag that may appear at this level or inside any group
    /// entry below it, sorted and unique.
    ///
    /// Iterative, so its depth is not bounded by the call stack; the tree it
    /// walks is itself bounded by [`MAX_SCOPE_DEPTH`] and [`MAX_SCOPE_NODES`].
    fn all_tags(&self) -> Vec<u32> {
        let mut tags = Vec::new();
        let mut pending: Vec<&Self> = vec![self];
        while let Some(level) = pending.pop() {
            tags.extend(level.members.iter().copied());
            pending.extend(level.groups.iter().map(|group| &group.entry));
        }
        tags.sort_unstable();
        tags.dedup();
        tags
    }
}

/// A repeating group and the level formed by one of its entries.
#[derive(Debug, Clone)]
pub(crate) struct LayoutGroup {
    /// Tag of the count field (NumInGroup).
    pub(crate) count_tag: u32,
    /// Group name, as the dictionary spells it.
    pub(crate) name: String,
    /// Tag every entry starts with.
    pub(crate) delimiter_tag: u32,
    /// Whether the group itself must appear at its level.
    pub(crate) required: bool,
    /// The level formed by one entry. Its required list holds each tag once
    /// and never the delimiter, which opens every entry.
    pub(crate) entry: Level,
}

/// The expanded schema of one message.
#[derive(Debug)]
pub(crate) struct Scope {
    /// The message level: header, trailer, and body merged.
    pub(crate) level: Level,
    /// Every tag the header and trailer contribute, members of header and
    /// trailer groups included, sorted and unique. These resolve against the
    /// transport dictionary.
    pub(crate) envelope: Vec<u32>,
}

/// Expands a [`MessageDef`] into the level tree the walks run against.
pub(crate) struct ScopeBuilder<'d> {
    /// The dictionary component references currently resolve against: the
    /// transport while the header and trailer are expanded, then the
    /// dictionary that defines the message body.
    dict: &'d Dictionary,
    budget: usize,
    errors: Vec<ValidationError>,
}

impl<'d> ScopeBuilder<'d> {
    /// Expands `msg_def` with its header and trailer from `transport` and its
    /// body components resolved against `body`, returning the scope and every
    /// schema error met on the way (ceilings, undefined components).
    ///
    /// For a single dictionary `transport` and `body` are the same one.
    pub(crate) fn expand(
        transport: &'d Dictionary,
        body: &'d Dictionary,
        msg_def: &MessageDef,
    ) -> (Scope, Vec<ValidationError>) {
        let mut builder = Self {
            dict: transport,
            budget: MAX_SCOPE_NODES,
            errors: Vec::new(),
        };
        let scope = builder.build(transport, body, msg_def);
        (scope, builder.errors)
    }

    /// Charges one node against the budget and checks the depth ceiling.
    fn spend(&mut self, name: &str, depth: usize) -> bool {
        if depth > MAX_SCOPE_DEPTH {
            self.errors.push(ValidationError::SchemaTooDeep {
                name: name.to_string(),
                limit: MAX_SCOPE_DEPTH,
            });
            return false;
        }
        match self.budget.checked_sub(1) {
            Some(remaining) => {
                self.budget = remaining;
                true
            }
            None => {
                if !self.errors.contains(&ValidationError::SchemaTooLarge {
                    limit: MAX_SCOPE_NODES,
                }) {
                    self.errors.push(ValidationError::SchemaTooLarge {
                        limit: MAX_SCOPE_NODES,
                    });
                }
                false
            }
        }
    }

    /// Builds the message level: header and trailer from `transport`, then
    /// body fields, groups, and directly referenced components from `body`.
    fn build(
        &mut self,
        transport: &'d Dictionary,
        body: &'d Dictionary,
        msg_def: &MessageDef,
    ) -> Scope {
        let mut level = Level::default();
        let mut path = HashSet::new();

        self.dict = transport;
        for field in &transport.header {
            level.add_field(field.tag, &field.name, field.required);
        }
        for group in &transport.header_groups {
            self.add_group(&mut level, group, group.required, true, 0, &mut path);
        }
        for field in &transport.trailer {
            level.add_field(field.tag, &field.name, field.required);
        }
        for group in &transport.trailer_groups {
            self.add_group(&mut level, group, group.required, true, 0, &mut path);
        }
        let envelope = level.all_tags();

        self.dict = body;
        for field in msg_def.fields() {
            level.add_field(field.tag, &field.name, field.required);
        }
        for group in msg_def.groups() {
            self.add_group(&mut level, group, group.required, true, 0, &mut path);
        }
        for component in msg_def.components() {
            self.add_component(&mut level, component, true, 0, &mut path);
        }
        level.finish();

        Scope { level, envelope }
    }

    /// Adds a group to `level` and builds the level formed by one entry.
    ///
    /// The group's component references resolve against `self.dict`.
    /// `required` and `collect_required` decide only whether the group itself
    /// must appear at `level`. The entry level always collects its members'
    /// required flags, because per the FIX rule they apply to every entry of
    /// every group instance present, whether or not the group is required:
    /// required fields, nested groups marked required, and the required
    /// members of components referenced as required. The required members of
    /// a component referenced as *optional* are never collected, even when
    /// some other member of that component appears in the entry. This is
    /// stricter than QuickFIX, which collects an entry's required fields only
    /// for a required group, and (in C++) none from components inside a group.
    fn add_group(
        &mut self,
        level: &mut Level,
        group: &GroupDef,
        required: bool,
        collect_required: bool,
        depth: usize,
        path: &mut HashSet<String>,
    ) {
        if !self.spend(&group.name, depth) {
            return;
        }
        level.members.push(group.count_tag);

        let mut entry = Level::default();
        entry.members.push(group.delimiter_tag);
        for field in group.fields() {
            entry.add_field(field.tag, &field.name, field.required);
        }
        for nested in group.groups() {
            self.add_group(&mut entry, nested, nested.required, true, depth + 1, path);
        }
        for component in group.components() {
            self.add_component(&mut entry, component, true, depth + 1, path);
        }
        // Each required tag is kept once, at its first (schema) position, so
        // the per-entry check is linear in the required set. The delimiter is
        // dropped: it opens every entry, so it can never be missing.
        let mut unique: HashSet<u32> = HashSet::with_capacity(entry.required.len());
        entry
            .required
            .retain(|(tag, _)| *tag != group.delimiter_tag && unique.insert(*tag));
        entry.finish();

        level.groups.push(LayoutGroup {
            count_tag: group.count_tag,
            name: group.name.clone(),
            delimiter_tag: group.delimiter_tag,
            required: required && collect_required,
            entry,
        });
    }

    /// Expands a component reference into `level`.
    ///
    /// The reference resolves against `self.dict`. `collect_required` says
    /// whether requiredness is meaningful where the reference sits; combined
    /// with the reference's own flag it gives the effective requiredness, so a
    /// component's required members can only make a message invalid when the
    /// reference that pulled it in was itself required.
    fn add_component(
        &mut self,
        level: &mut Level,
        reference: &ComponentRef,
        collect_required: bool,
        depth: usize,
        path: &mut HashSet<String>,
    ) {
        if !self.spend(&reference.name, depth) {
            return;
        }
        let Some(component) = self.dict.get_component(&reference.name) else {
            self.errors.push(ValidationError::UnknownComponent {
                name: reference.name.clone(),
            });
            return;
        };
        // A cycle can only reach here through a hand-built dictionary; the
        // loader rejects one. Expanding a component twice at different
        // places is legitimate, so the guard is per path, not global.
        if !path.insert(reference.name.clone()) {
            return;
        }

        let required = collect_required && reference.required;
        for field in component.fields() {
            level.add_field(field.tag, &field.name, required && field.required);
        }
        for group in component.groups() {
            self.add_group(level, group, group.required, required, depth + 1, path);
        }
        for nested in component.components() {
            self.add_component(level, nested, required, depth + 1, path);
        }

        path.remove(&reference.name);
    }
}
