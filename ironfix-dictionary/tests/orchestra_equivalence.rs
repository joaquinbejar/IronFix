/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 22/10/26
******************************************************************************/

//! Compares every Orchestra repository vendored under `fixtures/orchestra`
//! (see its README for provenance) with the embedded QuickFIX dictionary of
//! the same version: FIX 4.2, FIX 4.4, FIXT 1.1 and FIX 5.0 SP2 (derived from
//! the FIX Latest repository with `Dictionary::from_orchestra_latest_xml`).
//!
//! The diff covers fields (tag, name, type, enumeration values), messages
//! (message type, name, category, required fields), components (name, the
//! tags they can carry), the header and trailer, and repeating groups
//! (delimiter, member order). It is computed flattened, through components:
//! Orchestra holds some blocks as groups where QuickFIX wraps the group in a
//! component (`Parties`), so the two models only agree once components are
//! expanded.
//!
//! Each difference is one line, classed `orchestra-only`, `quickfix-only` or
//! `conflict`. The known differences are an explicit allowlist, one file per
//! version under `orchestra_equivalence/`, and `doc/orchestra_differences.md`
//! summarises and justifies them. A difference missing from the allowlist
//! fails the test, and so does an allowlisted one that no longer occurs.

use ironfix_dictionary::{
    Dictionary, DictionaryError, FieldType, MemberRef, MessageCategory, OrchestraImport,
    SessionDictionary, Validator, Version,
};
use ironfix_tagvalue::Decoder;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

const ORCHESTRA_FIX42: &str = include_str!("fixtures/orchestra/OrchestraFIX42.xml");
const ORCHESTRA_FIX44: &str = include_str!("fixtures/orchestra/OrchestraFIX44.xml");
const ORCHESTRA_FIXT: &str = include_str!("fixtures/orchestra/FIXTSession.xml");
const ORCHESTRA_FIX_LATEST: &str = include_str!("fixtures/orchestra/OrchestraFIXLatest.xml");

const ALLOWED_FIX42: &str = include_str!("orchestra_equivalence/fix42.txt");
const ALLOWED_FIX44: &str = include_str!("orchestra_equivalence/fix44.txt");
const ALLOWED_FIXT11: &str = include_str!("orchestra_equivalence/fixt11.txt");
const ALLOWED_FIX50SP2: &str = include_str!("orchestra_equivalence/fix50sp2.txt");

/// Unwraps a `Result` with test context instead of `.unwrap()`.
#[track_caller]
fn ok<T, E: Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what}: {err:?}"),
    }
}

/// A member list flattened through components.
#[derive(Debug, Default)]
struct Flat {
    /// Every tag the list can carry, at any depth.
    tags: BTreeSet<u32>,
    /// Tags reached through required members only, outside every group.
    required: BTreeSet<u32>,
    /// Per group, keyed by its path of count tags (`453/802`): its delimiter
    /// and its entry-level members in order (field tags and the count tags
    /// of nested groups, components expanded in place).
    groups: BTreeMap<String, (u32, Vec<u32>)>,
}

/// Appends the entry-level tags of `members`, components expanded, to
/// `order`.
fn entry_order<'d>(
    dict: &'d Dictionary,
    members: impl Iterator<Item = MemberRef<'d>>,
    order: &mut Vec<u32>,
) {
    for member in members {
        match member {
            MemberRef::Field(field) => order.push(field.tag),
            MemberRef::Group(group) => order.push(group.count_tag),
            MemberRef::Component(component) => {
                let Some(def) = dict.get_component(&component.name) else {
                    panic!("component {} is defined", component.name);
                };
                entry_order(dict, def.members(), order);
            }
        }
    }
}

fn flatten<'d>(
    dict: &'d Dictionary,
    members: impl Iterator<Item = MemberRef<'d>>,
    path: &str,
    required_path: bool,
    flat: &mut Flat,
) {
    for member in members {
        match member {
            MemberRef::Field(field) => {
                flat.tags.insert(field.tag);
                if required_path && path.is_empty() && field.required {
                    flat.required.insert(field.tag);
                }
            }
            MemberRef::Group(group) => {
                flat.tags.insert(group.count_tag);
                if required_path && path.is_empty() && group.required {
                    flat.required.insert(group.count_tag);
                }
                let inner = if path.is_empty() {
                    group.count_tag.to_string()
                } else {
                    format!("{path}/{}", group.count_tag)
                };
                let mut order = Vec::new();
                entry_order(dict, group.members(), &mut order);
                flat.groups
                    .insert(inner.clone(), (group.delimiter_tag, order));
                flatten(dict, group.members(), &inner, false, flat);
            }
            MemberRef::Component(component) => {
                let Some(def) = dict.get_component(&component.name) else {
                    panic!("component {} is defined", component.name);
                };
                flatten(
                    dict,
                    def.members(),
                    path,
                    required_path && component.required,
                    flat,
                );
            }
        }
    }
}

/// The header (`true`) or trailer (`false`) of `dict`, flattened.
fn flat_envelope(dict: &Dictionary, header: bool) -> Flat {
    let (fields, groups) = if header {
        (&dict.header, &dict.header_groups)
    } else {
        (&dict.trailer, &dict.trailer_groups)
    };
    let mut flat = Flat::default();
    flatten(
        dict,
        fields.iter().map(MemberRef::Field),
        "",
        true,
        &mut flat,
    );
    flatten(
        dict,
        groups.iter().map(MemberRef::Group),
        "",
        true,
        &mut flat,
    );
    flat
}

/// `set` as a compact, sorted list.
fn list<'a>(set: impl IntoIterator<Item = &'a u32>) -> String {
    let mut tags: Vec<u32> = set.into_iter().copied().collect();
    tags.sort_unstable();
    format!("{tags:?}")
}

/// The differences between two sets, as `orchestra-only` / `quickfix-only`
/// lines about `what`.
fn set_diff(out: &mut Vec<String>, what: &str, o: &BTreeSet<u32>, q: &BTreeSet<u32>) {
    let only_o: Vec<&u32> = o.difference(q).collect();
    let only_q: Vec<&u32> = q.difference(o).collect();
    if !only_o.is_empty() {
        out.push(format!("orchestra-only {what} {}", list(only_o)));
    }
    if !only_q.is_empty() {
        out.push(format!("quickfix-only {what} {}", list(only_q)));
    }
}

/// The differences between two flattened member lists under `scope`.
fn flat_diff(out: &mut Vec<String>, scope: &str, o: &Flat, q: &Flat) {
    set_diff(out, &format!("{scope} tags"), &o.tags, &q.tags);
    set_diff(out, &format!("{scope} required"), &o.required, &q.required);
    // Groups both sides hold at the same path: delimiter and member order.
    // Which groups each side holds at all is compared over the whole
    // dictionary, by count tag, in `differences`.
    for (path, (o_delim, o_order)) in &o.groups {
        let Some((q_delim, q_order)) = q.groups.get(path) else {
            continue;
        };
        let count = path.rsplit('/').next().unwrap_or(path);
        if o_delim != q_delim {
            out.push(format!(
                "conflict group {count} delimiter: orchestra {o_delim} quickfix {q_delim}"
            ));
        }
        // Order of the members both list; a member only one lists is
        // already a `tags` difference.
        let o_set: BTreeSet<u32> = o_order.iter().copied().collect();
        let q_set: BTreeSet<u32> = q_order.iter().copied().collect();
        let o_common: Vec<u32> = o_order
            .iter()
            .copied()
            .filter(|tag| q_set.contains(tag))
            .collect();
        let q_common: Vec<u32> = q_order
            .iter()
            .copied()
            .filter(|tag| o_set.contains(tag))
            .collect();
        if o_common != q_common {
            out.push(format!(
                "conflict group {count} order: orchestra {o_common:?} quickfix {q_common:?}"
            ));
        }
    }
}

/// The count tags of every group `flat` holds, at any depth.
fn group_tags(flat: &Flat, tags: &mut BTreeSet<u32>) {
    for path in flat.groups.keys() {
        if let Some(Ok(tag)) = path.rsplit('/').next().map(str::parse::<u32>) {
            tags.insert(tag);
        }
    }
}

/// The names of the components of `dict` that are more than a wrapper
/// around a single repeating group.
fn component_names(dict: &Dictionary) -> BTreeSet<&String> {
    dict.components
        .iter()
        .filter(|(_, def)| {
            let mut members = def.members();
            !(members.len() == 1 && matches!(members.next(), Some(MemberRef::Group(_))))
        })
        .map(|(name, _)| name)
        .collect()
}

/// Every difference between `orchestra` and `quickfix`, one line each.
fn differences(orchestra: &Dictionary, quickfix: &Dictionary) -> Vec<String> {
    let mut out = Vec::new();

    // Fields: tag, name, type, enumeration values.
    let o_tags: BTreeSet<u32> = orchestra.fields.keys().copied().collect();
    let q_tags: BTreeSet<u32> = quickfix.fields.keys().copied().collect();
    set_diff(&mut out, "fields", &o_tags, &q_tags);
    for tag in o_tags.intersection(&q_tags) {
        let (Some(o), Some(q)) = (orchestra.get_field(*tag), quickfix.get_field(*tag)) else {
            panic!("tag {tag} is defined in both");
        };
        if o.name != q.name {
            out.push(format!(
                "conflict field {tag} name: orchestra {} quickfix {}",
                o.name, q.name
            ));
        }
        if o.field_type != q.field_type {
            out.push(format!(
                "conflict field {tag} type: orchestra {:?} quickfix {:?}",
                o.field_type, q.field_type
            ));
        }
        let o_values: BTreeSet<&String> = o.values.iter().flat_map(|v| v.keys()).collect();
        let q_values: BTreeSet<&String> = q.values.iter().flat_map(|v| v.keys()).collect();
        let only_o: Vec<&&String> = o_values.difference(&q_values).collect();
        let only_q: Vec<&&String> = q_values.difference(&o_values).collect();
        if !only_o.is_empty() {
            out.push(format!("orchestra-only field {tag} values {only_o:?}"));
        }
        if !only_q.is_empty() {
            out.push(format!("quickfix-only field {tag} values {only_q:?}"));
        }
    }

    // Header and trailer.
    let mut o_groups = BTreeSet::new();
    let mut q_groups = BTreeSet::new();
    for (header, scope) in [(true, "header"), (false, "trailer")] {
        let (o_flat, q_flat) = (
            flat_envelope(orchestra, header),
            flat_envelope(quickfix, header),
        );
        group_tags(&o_flat, &mut o_groups);
        group_tags(&q_flat, &mut q_groups);
        flat_diff(&mut out, scope, &o_flat, &q_flat);
    }

    // Components: name, and the tags each can carry. A component that only
    // wraps one repeating group is the QuickFIX spelling of what Orchestra
    // holds as a group (`Parties`); its content is compared where messages
    // use it, so it is left out here.
    let o_names: BTreeSet<&String> = component_names(orchestra);
    let q_names: BTreeSet<&String> = component_names(quickfix);
    for name in o_names.difference(&q_names) {
        out.push(format!("orchestra-only component {name}"));
    }
    for name in q_names.difference(&o_names) {
        out.push(format!("quickfix-only component {name}"));
    }
    for name in o_names.intersection(&q_names) {
        let (Some(o), Some(q)) = (orchestra.get_component(name), quickfix.get_component(name))
        else {
            panic!("component {name} is defined in both");
        };
        let mut o_flat = Flat::default();
        flatten(orchestra, o.members(), "", true, &mut o_flat);
        let mut q_flat = Flat::default();
        flatten(quickfix, q.members(), "", true, &mut q_flat);
        set_diff(
            &mut out,
            &format!("component {name} tags"),
            &o_flat.tags,
            &q_flat.tags,
        );
    }

    // Messages: type, name, category, required fields, groups.
    let o_types: BTreeSet<&String> = orchestra.messages.keys().collect();
    let q_types: BTreeSet<&String> = quickfix.messages.keys().collect();
    for msg_type in o_types.difference(&q_types) {
        out.push(format!("orchestra-only message {msg_type}"));
    }
    for msg_type in q_types.difference(&o_types) {
        out.push(format!("quickfix-only message {msg_type}"));
    }
    for msg_type in o_types.intersection(&q_types) {
        let (Some(o), Some(q)) = (
            orchestra.get_message(msg_type),
            quickfix.get_message(msg_type),
        ) else {
            panic!("message {msg_type} is defined in both");
        };
        if o.name != q.name {
            out.push(format!(
                "conflict message {msg_type} name: orchestra {} quickfix {}",
                o.name, q.name
            ));
        }
        if o.category != q.category {
            out.push(format!(
                "conflict message {msg_type} category: orchestra {:?} quickfix {:?}",
                o.category, q.category
            ));
        }
        let mut o_flat = Flat::default();
        flatten(orchestra, o.members(), "", true, &mut o_flat);
        let mut q_flat = Flat::default();
        flatten(quickfix, q.members(), "", true, &mut q_flat);
        flat_diff(&mut out, &format!("message {msg_type}"), &o_flat, &q_flat);
    }
    // Groups, by count tag, over every message either side defines.
    for message in orchestra.messages() {
        let mut flat = Flat::default();
        flatten(orchestra, message.members(), "", true, &mut flat);
        group_tags(&flat, &mut o_groups);
    }
    for message in quickfix.messages() {
        let mut flat = Flat::default();
        flatten(quickfix, message.members(), "", true, &mut flat);
        group_tags(&flat, &mut q_groups);
    }
    set_diff(&mut out, "groups", &o_groups, &q_groups);
    // A group conflict found in many messages is one difference.
    out.sort();
    out.dedup();
    out
}

/// The allowlisted lines of `allowlist`: every line that is neither blank
/// nor a `#` comment.
fn allowed(allowlist: &str) -> Vec<&str> {
    allowlist
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

/// Loads `xml` with [`Dictionary::from_orchestra_xml`].
fn load(xml: &str) -> OrchestraImport {
    ok(Dictionary::from_orchestra_xml(xml), "the repository loads")
}

/// Derives the FIX 5.0 SP2 dictionary from the FIX Latest repository.
fn fix50sp2_from_latest() -> OrchestraImport {
    ok(
        Dictionary::from_orchestra_latest_xml(ORCHESTRA_FIX_LATEST, Version::Fix50Sp2),
        "FIX 5.0 SP2 derives from FIX Latest",
    )
}

/// Checks the version of `import`, and compares it with `quickfix` against
/// `allowlist`.
#[track_caller]
fn check(import: &OrchestraImport, version: Version, quickfix: &Dictionary, allowlist: &str) {
    assert_eq!(import.dictionary().version, version);
    assert_eq!(quickfix.version, version);
    let found = differences(import.dictionary(), quickfix);
    let expected = allowed(allowlist);
    let found_set: BTreeSet<&str> = found.iter().map(String::as_str).collect();
    let expected_set: BTreeSet<&str> = expected.iter().copied().collect();
    let new: Vec<&&str> = found_set.difference(&expected_set).collect();
    let gone: Vec<&&str> = expected_set.difference(&found_set).collect();
    assert!(
        new.is_empty() && gone.is_empty(),
        "{version:?}: {} differences not allowlisted:\n{}\n{} allowlisted differences no longer found:\n{}",
        new.len(),
        new.iter()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n"),
        gone.len(),
        gone.iter()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    assert_eq!(
        found.len(),
        expected.len(),
        "{version:?}: duplicate allowlist lines"
    );
}

#[test]
fn test_orchestra_fix42_matches_quickfix_but_for_the_allowlist() {
    let quickfix = ok(Dictionary::fix42(), "the embedded FIX 4.2 dictionary loads");
    check(
        &load(ORCHESTRA_FIX42),
        Version::Fix42,
        quickfix,
        ALLOWED_FIX42,
    );
}

#[test]
fn test_orchestra_fix44_matches_quickfix_but_for_the_allowlist() {
    let quickfix = ok(Dictionary::fix44(), "the embedded FIX 4.4 dictionary loads");
    check(
        &load(ORCHESTRA_FIX44),
        Version::Fix44,
        quickfix,
        ALLOWED_FIX44,
    );
}

#[test]
fn test_orchestra_fixt_session_matches_quickfix_but_for_the_allowlist() {
    let quickfix = ok(
        Dictionary::fixt11(),
        "the embedded FIXT 1.1 dictionary loads",
    );
    check(
        &load(ORCHESTRA_FIXT),
        Version::Fixt11,
        quickfix,
        ALLOWED_FIXT11,
    );
}

#[test]
fn test_orchestra_fix50sp2_matches_quickfix_but_for_the_allowlist() {
    let quickfix = ok(
        Dictionary::fix50sp2(),
        "the embedded FIX 5.0 SP2 dictionary loads",
    );
    check(
        &fix50sp2_from_latest(),
        Version::Fix50Sp2,
        quickfix,
        ALLOWED_FIX50SP2,
    );
}

/// FIX 4.4 as Orchestra types the two fields whose code set QuickFIX types
/// `STRING`; a typed conflict, decided for Orchestra.
#[test]
fn test_orchestra_fix44_types_its_int_code_sets_int() {
    let import = ok(
        Dictionary::from_orchestra_xml(ORCHESTRA_FIX44),
        "FIX 4.4 loads",
    );
    for tag in [532, 674] {
        let Some(field) = import.dictionary().get_field(tag) else {
            panic!("tag {tag} is defined");
        };
        assert_eq!(field.field_type, FieldType::Int, "tag {tag}");
    }
}

#[test]
fn test_fix50sp2_from_latest_holds_every_quickfix_message() {
    let import = fix50sp2_from_latest();
    let derived = import.dictionary();
    let Ok(quickfix) = Dictionary::fix50sp2() else {
        panic!("the embedded FIX 5.0 SP2 dictionary loads");
    };
    assert_eq!(quickfix.messages.len(), 156);
    // Every QuickFIX message, and the eight FIXT session messages FIX
    // Latest carries and QuickFIX keeps in FIXT11.xml.
    assert_eq!(derived.messages.len(), 164);
    for msg_type in quickfix.messages.keys() {
        assert!(derived.get_message(msg_type).is_some(), "{msg_type}");
    }
    let session: BTreeSet<&str> = derived
        .messages()
        .filter(|message| message.category == MessageCategory::Admin)
        .map(|message| message.msg_type.as_str())
        .collect();
    assert_eq!(
        session,
        BTreeSet::from(["0", "1", "2", "3", "4", "5", "A", "n"])
    );
    // Added after FIX 5.0 SP2, in FIX Latest: left out.
    assert!(derived.get_message("EC").is_none());
}

#[test]
fn test_fix_latest_is_only_read_through_the_targeted_import() {
    assert_eq!(
        Dictionary::from_orchestra_xml(ORCHESTRA_FIX_LATEST).err(),
        Some(DictionaryError::UnsupportedVersion(
            "FIX.Latest_EP312".to_owned()
        ))
    );
    assert_eq!(
        Dictionary::from_orchestra_latest_xml(ORCHESTRA_FIX_LATEST, Version::Fix44).err(),
        Some(DictionaryError::UnsupportedVersion(
            "Fix44 from FIX.Latest".to_owned()
        ))
    );
    assert_eq!(
        Dictionary::from_orchestra_latest_xml(ORCHESTRA_FIX44, Version::Fix50Sp2).err(),
        Some(DictionaryError::UnsupportedVersion(
            "FIX.4.4_EP311 (expected FIX.Latest)".to_owned()
        ))
    );
}

#[test]
fn test_orchestra_fix42_session_messages_are_admin_without_categories() {
    let import = load(ORCHESTRA_FIX42);
    let admin: BTreeSet<&str> = import
        .dictionary()
        .messages()
        .filter(|message| message.category == MessageCategory::Admin)
        .map(|message| message.msg_type.as_str())
        .collect();
    assert_eq!(admin, BTreeSet::from(["0", "1", "2", "3", "4", "5", "A"]));
}

/// Builds a FIXT.1.1 frame with a computed body length and a placeholder
/// checksum (the decoder below does not check it).
fn fixt_frame(body: &[&str]) -> String {
    let body: String = body.iter().map(|field| format!("{field}\x01")).collect();
    format!("8=FIXT.1.1\x019={}\x01{body}10=000\x01", body.len())
}

/// The Orchestra FIXT session repository lists only the session message
/// types for MsgType(35) and RefMsgType(372); composed with an application
/// dictionary, the application's message types are valid too.
#[test]
fn test_orchestra_fixt_composed_with_fix50sp2_accepts_application_msg_types() {
    let transport = load(ORCHESTRA_FIXT);
    let application = fix50sp2_from_latest();
    let session = ok(
        SessionDictionary::new(transport.dictionary(), application.dictionary()),
        "FIXT 1.1 composes with FIX 5.0 SP2",
    );
    let validator = Validator::for_session(&session);
    let order = fixt_frame(&[
        "35=D",
        "49=CLIENT",
        "56=BROKER",
        "34=2",
        "52=20260718-10:00:00",
        "1128=9",
        "11=ORDER-1",
        "55=EURUSD",
        "54=1",
        "60=20260718-10:00:00",
        "38=100",
        "40=1",
    ]);
    let mut decoder = Decoder::new(order.as_bytes()).with_checksum_validation(false);
    let msg = ok(decoder.decode(), "the order decodes");
    assert_eq!(validator.validate(&msg), Ok(()));

    // A session Reject naming an application message type.
    let reject = fixt_frame(&[
        "35=3",
        "49=CLIENT",
        "56=BROKER",
        "34=3",
        "52=20260718-10:00:00",
        "45=2",
        "372=D",
    ]);
    let mut decoder = Decoder::new(reject.as_bytes()).with_checksum_validation(false);
    let msg = ok(decoder.decode(), "the reject decodes");
    assert_eq!(validator.validate(&msg), Ok(()));

    // A message type neither side defines is still unknown.
    let bogus = fixt_frame(&[
        "35=3",
        "49=CLIENT",
        "56=BROKER",
        "34=4",
        "52=20260718-10:00:00",
        "45=2",
        "372=ZZ",
    ]);
    let mut decoder = Decoder::new(bogus.as_bytes()).with_checksum_validation(false);
    let msg = ok(decoder.decode(), "the bogus reject decodes");
    assert!(validator.validate(&msg).is_err());
}
