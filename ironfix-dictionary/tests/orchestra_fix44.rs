/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Loads the FIX Trading Community's FIX 4.4 Orchestra repository
//! (`fixtures/orchestra/OrchestraFIX44.xml`, see its README for provenance)
//! and compares it with the embedded QuickFIX FIX 4.4 dictionary.
//!
//! Orchestra holds some blocks as repeating groups where QuickFIX wraps the
//! group in a component (`Parties` is a group in Orchestra, a component
//! holding the `NoPartyIDs` group in QuickFIX), so the two are compared
//! flattened: per message, every tag a message can carry, the tags it must
//! carry, each group's count and delimiter tags, and, per group at every
//! nesting level, the tags each entry must carry. Every difference is listed
//! below with its cause.

use ironfix_dictionary::{
    Dictionary, FieldType, MemberRef, MessageCategory, OrchestraImport, UnmappedConstruct,
    Validator, Version,
};
use ironfix_tagvalue::Decoder;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

const ORCHESTRA_FIX44: &str = include_str!("fixtures/orchestra/OrchestraFIX44.xml");

/// Unwraps a `Result` with test context instead of `.unwrap()`.
#[track_caller]
fn ok<T, E: Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what}: {err:?}"),
    }
}

fn orchestra() -> OrchestraImport {
    ok(
        Dictionary::from_orchestra_xml(ORCHESTRA_FIX44),
        "the FIX 4.4 Orchestra repository loads",
    )
}

fn quickfix() -> &'static Dictionary {
    ok(Dictionary::fix44(), "the embedded FIX 4.4 dictionary loads")
}

/// A member list flattened through components and groups.
#[derive(Debug, Default, PartialEq, Eq)]
struct Flat {
    /// Every tag the list can carry, at any depth.
    tags: BTreeSet<u32>,
    /// Tags reached through required members only, outside every group.
    required: BTreeSet<u32>,
    /// `(count tag, delimiter tag)` of every group, at any depth.
    groups: BTreeSet<(u32, u32)>,
    /// Per group, keyed by its path of count tags (`453/802`): the tags an
    /// entry must carry, reached through required members only, outside the
    /// groups nested in it.
    entries: BTreeMap<String, BTreeSet<u32>>,
}

impl Flat {
    /// The required set of the message level (`path` empty) or of a group.
    fn required_at(&mut self, path: &str) -> &mut BTreeSet<u32> {
        if path.is_empty() {
            &mut self.required
        } else {
            self.entries.entry(path.to_owned()).or_default()
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
                if required_path && field.required {
                    flat.required_at(path).insert(field.tag);
                }
            }
            MemberRef::Group(group) => {
                flat.tags.insert(group.count_tag);
                if required_path && group.required {
                    flat.required_at(path).insert(group.count_tag);
                }
                flat.groups.insert((group.count_tag, group.delimiter_tag));
                // Inside a group, a member is required per entry: its own
                // set, under the group's path.
                let inner = if path.is_empty() {
                    group.count_tag.to_string()
                } else {
                    format!("{path}/{}", group.count_tag)
                };
                flat.required_at(&inner);
                flatten(dict, group.members(), &inner, true, flat);
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

/// Every message of `dict`, flattened, keyed by message type.
fn flat_messages(dict: &Dictionary) -> BTreeMap<String, Flat> {
    dict.messages()
        .map(|message| {
            let mut flat = Flat::default();
            flatten(dict, message.members(), "", true, &mut flat);
            (message.msg_type.clone(), flat)
        })
        .collect()
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

fn sorted(set: impl IntoIterator<Item = u32>) -> Vec<u32> {
    let mut list: Vec<u32> = set.into_iter().collect();
    list.sort_unstable();
    list
}

#[test]
fn test_orchestra_fix44_loads_as_fix44() {
    let import = orchestra();
    let dict = import.dictionary();
    assert_eq!(dict.version, Version::Fix44);
    assert_eq!(dict.fields.len(), 912);
    assert_eq!(dict.messages.len(), 93);
    // 15 Orchestra components, less StandardHeader and StandardTrailer,
    // which become the dictionary's header and trailer.
    assert_eq!(dict.components.len(), 13);
    assert!(dict.get_component("StandardHeader").is_none());
    assert!(dict.get_component("Instrument").is_some());
    // Orchestra holds Parties as a group, not a component.
    assert!(dict.get_component("Parties").is_none());
    assert_eq!(dict.header.len(), 26);
    assert_eq!(dict.header_groups.len(), 1);
    assert_eq!(dict.trailer.len(), 3);
}

#[test]
fn test_orchestra_fix44_names_groups_after_their_count_field() {
    let import = orchestra();
    let Some(order) = import.dictionary().get_message("D") else {
        panic!("NewOrderSingle is defined");
    };
    let Some(parties) = order.groups().iter().find(|g| g.count_tag == 453) else {
        panic!("NewOrderSingle holds the Parties group");
    };
    // QuickFIX's name, the count field's; the Orchestra group is `Parties`.
    assert_eq!(parties.name, "NoPartyIDs");
    assert_eq!(parties.delimiter_tag, 448);
    assert!(!parties.required);
    // Nested PtysSubGrp, also named after its count field.
    let names: Vec<&str> = parties.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["NoPartySubIDs"]);
    // The message keeps the repository's member order: ClOrdID(11) then
    // SecondaryClOrdID(526), ClOrdLinkID(583), the Parties group.
    let first: Vec<String> = order
        .members()
        .take(4)
        .map(|member| match member {
            MemberRef::Field(field) => format!("field {}", field.tag),
            MemberRef::Group(group) => format!("group {}", group.count_tag),
            MemberRef::Component(component) => format!("component {}", component.name),
        })
        .collect();
    assert_eq!(
        first,
        ["field 11", "field 526", "field 583", "group 453"],
        "member order"
    );
}

#[test]
fn test_orchestra_fix44_report_lists_what_the_model_cannot_hold() {
    let import = orchestra();
    let mut by_attribute: BTreeMap<String, usize> = BTreeMap::new();
    let mut unreferenced = Vec::new();
    for entry in import.report().entries() {
        match entry {
            UnmappedConstruct::Attribute { name, .. } => {
                *by_attribute.entry(name.clone()).or_default() += 1;
            }
            UnmappedConstruct::Unreferenced { kind, name, .. } => {
                unreferenced.push(format!("{kind} {name}"));
            }
            other => panic!("only attributes and unreferenced definitions, not {other}"),
        }
    }
    // ExecsGrp (NoExecs, 124) is defined, and checked, but no message or
    // component of the repository references it.
    assert_eq!(unreferenced, ["group ExecsGrp"]);
    let expected: BTreeMap<String, usize> = [
        // The LENGTH field of each data field (Signature(89) -> 93, ...).
        ("lengthId", 16),
        // The source field of each identifier (SecurityID(48) -> 22, ...).
        ("discriminatorId", 12),
        // A second type a value may take (IOIQty(27) is S/M/L or a Qty).
        ("unionDataType", 10),
        // AllocGrp and TrdCapRptSideGrp.
        ("implMaxOccurs", 2),
    ]
    .into_iter()
    .map(|(name, count)| (name.to_owned(), count))
    .collect();
    assert_eq!(by_attribute, expected);
    assert_eq!(import.report().len(), 41);
}

#[test]
fn test_orchestra_fix44_fields_match_quickfix() {
    let import = orchestra();
    let orchestra = import.dictionary();
    let quickfix = quickfix();
    let tags: BTreeSet<u32> = orchestra.fields.keys().copied().collect();
    assert_eq!(
        tags,
        quickfix.fields.keys().copied().collect::<BTreeSet<u32>>()
    );

    let mut names = Vec::new();
    let mut types = Vec::new();
    let mut more_values = Vec::new();
    for tag in tags {
        let (Some(o), Some(q)) = (orchestra.get_field(tag), quickfix.get_field(tag)) else {
            panic!("tag {tag} is defined in both");
        };
        if o.name != q.name {
            names.push((tag, q.name.clone(), o.name.clone()));
        }
        if o.field_type != q.field_type {
            types.push((tag, q.field_type, o.field_type));
        }
        let o_values: BTreeSet<&String> = o.values.iter().flat_map(|v| v.keys()).collect();
        let q_values: BTreeSet<&String> = q.values.iter().flat_map(|v| v.keys()).collect();
        // QuickFIX never declares a value Orchestra lacks.
        assert!(
            q_values.is_subset(&o_values),
            "tag {tag}: QuickFIX values {:?} missing from Orchestra",
            q_values.difference(&o_values).collect::<Vec<_>>()
        );
        if o_values.len() > q_values.len() {
            more_values.push(tag);
        }
    }
    // The two files name tag 327 differently.
    assert_eq!(
        names,
        [(327, "HaltReasonChar".to_owned(), "HaltReason".to_owned())]
    );
    // Orchestra types both fields' code sets `int`; QuickFIX types the
    // fields STRING (see the fixture README for 532).
    assert_eq!(
        types,
        [
            (532, FieldType::String, FieldType::Int),
            (674, FieldType::String, FieldType::Int)
        ]
    );
    // Fields whose code set Orchestra carries and QuickFIX leaves out or
    // carries in part; among them the nested party roles and sources, the
    // security identifier sources, RefMsgType(372), and single values such
    // as ExecInst(18) `T`, OrdStatus(39) `5` and OrdRejReason(103) `12`.
    assert_eq!(
        more_values,
        [
            18, 39, 103, 221, 305, 368, 372, 456, 459, 487, 525, 538, 564, 587, 603, 606, 661, 674,
            677, 758, 759, 761, 776, 783, 784, 786, 805, 807, 888, 950, 951, 954
        ]
    );
}

#[test]
fn test_orchestra_fix44_header_and_trailer_match_quickfix() {
    let import = orchestra();
    for header in [true, false] {
        assert_eq!(
            flat_envelope(import.dictionary(), header),
            flat_envelope(quickfix(), header),
            "header {header}"
        );
    }
}

#[test]
fn test_orchestra_fix44_messages_match_quickfix_flattened() {
    let import = orchestra();
    let orchestra = import.dictionary();
    let quickfix = quickfix();
    let o_messages = flat_messages(orchestra);
    let q_messages = flat_messages(quickfix);
    assert_eq!(
        o_messages.keys().collect::<Vec<_>>(),
        q_messages.keys().collect::<Vec<_>>()
    );

    let mut differences = Vec::new();
    let mut group_paths = 0;
    for (msg_type, o) in &o_messages {
        let q = &q_messages[msg_type];
        let (Some(o_def), Some(q_def)) = (
            orchestra.get_message(msg_type),
            quickfix.get_message(msg_type),
        ) else {
            panic!("message {msg_type} is defined in both");
        };
        assert_eq!(o_def.name, q_def.name, "message {msg_type} name");
        assert_eq!(
            o_def.category, q_def.category,
            "message {msg_type} category"
        );
        let only_o = sorted(o.tags.difference(&q.tags).copied());
        let only_q = sorted(q.tags.difference(&o.tags).copied());
        if !only_o.is_empty() || !only_q.is_empty() {
            differences.push(format!("{msg_type} tags: +{only_o:?} -{only_q:?}"));
        }
        let only_o = sorted(o.required.difference(&q.required).copied());
        let only_q = sorted(q.required.difference(&o.required).copied());
        if !only_o.is_empty() || !only_q.is_empty() {
            differences.push(format!("{msg_type} required: +{only_o:?} -{only_q:?}"));
        }
        let only_o: Vec<_> = o.groups.difference(&q.groups).collect();
        let only_q: Vec<_> = q.groups.difference(&o.groups).collect();
        if !only_o.is_empty() || !only_q.is_empty() {
            differences.push(format!("{msg_type} groups: +{only_o:?} -{only_q:?}"));
        }
        group_paths += o.entries.len();
        let paths: BTreeSet<&String> = o.entries.keys().chain(q.entries.keys()).collect();
        for path in paths {
            let empty = BTreeSet::new();
            let o_entry = o.entries.get(path).unwrap_or(&empty);
            let q_entry = q.entries.get(path).unwrap_or(&empty);
            let only_o = sorted(o_entry.difference(q_entry).copied());
            let only_q = sorted(q_entry.difference(o_entry).copied());
            if !o.entries.contains_key(path) || !q.entries.contains_key(path) {
                differences.push(format!("{msg_type} group {path}: in one dictionary only"));
            } else if !only_o.is_empty() || !only_q.is_empty() {
                differences.push(format!(
                    "{msg_type} group {path} required: +{only_o:?} -{only_q:?}"
                ));
            }
        }
    }
    // Every group of every message, at every nesting level, by its path of
    // count tags: the per-entry required sets agree on all of them.
    assert_eq!(group_paths, 730, "group paths compared");
    // `+` is Orchestra only, `-` QuickFIX only.
    let expected = [
        // Orchestra lists ClearingFeeIndicator(635) in TrdCapRptSideGrp;
        // QuickFIX's TradeCaptureReport side group leaves it out.
        "AE tags: +[635] -[]",
        // Orchestra models these blocks as groups and marks the reference
        // required; QuickFIX wraps an optional group in a component and
        // marks the component required (UndInstrmtGrp, InstrmtLegGrp,
        // Parties, PositionQty, PositionAmountData). Flattened, the required
        // flag lands on the count tag only in Orchestra: NoLegs(555),
        // NoUnderlyings(711), NoPartyIDs(453), NoPositions(702),
        // NoPosAmt(753).
        "AK required: +[555, 711] -[]",
        "AL required: +[453, 702] -[]",
        "AM required: +[702, 753] -[]",
        "AN required: +[453] -[]",
        "AO required: +[453] -[]",
        "AP required: +[453, 702, 753] -[]",
        "AW required: +[453, 702, 753] -[]",
        // Orchestra marks CollInquiryID(909) required in CollateralInquiry;
        // QuickFIX does not.
        "BB required: +[909] -[]",
        // Orchestra lists OrigOrdModTime(586) in SideCrossOrdModGrp;
        // QuickFIX's cross-order side group leaves it out.
        "s tags: +[586] -[]",
        "t tags: +[586] -[]",
    ];
    assert_eq!(differences, expected);
}

/// Builds a FIX 4.4 frame with a computed body length and a placeholder
/// checksum (the decoder below does not check it).
fn frame(body: &[&str]) -> String {
    let body: String = body.iter().map(|field| format!("{field}\x01")).collect();
    format!("8=FIX.4.4\x019={}\x01{body}10=000\x01", body.len())
}

#[test]
fn test_orchestra_fix44_validates_like_quickfix() {
    let import = orchestra();
    let order = frame(&[
        "35=D",
        "49=CLIENT",
        "56=BROKER",
        "34=2",
        "52=20260718-10:00:00",
        "11=ORDER-1",
        "453=1",
        "448=TRADER",
        "447=D",
        "452=11",
        "21=1",
        "55=EURUSD",
        "54=1",
        "60=20260718-10:00:00",
        "38=100",
        "40=2",
        "44=1.2345",
    ]);
    let mut decoder = Decoder::new(order.as_bytes()).with_checksum_validation(false);
    let msg = ok(decoder.decode(), "the order decodes");
    assert_eq!(Validator::new(import.dictionary()).validate(&msg), Ok(()));
    assert_eq!(Validator::new(quickfix()).validate(&msg), Ok(()));

    // A missing required field and an undeclared Side are reported alike.
    let bad = frame(&[
        "35=D",
        "49=CLIENT",
        "56=BROKER",
        "34=2",
        "52=20260718-10:00:00",
        "11=ORDER-1",
        "21=1",
        "55=EURUSD",
        "54=Z",
        "60=20260718-10:00:00",
        "38=100",
    ]);
    let mut decoder = Decoder::new(bad.as_bytes()).with_checksum_validation(false);
    let msg = ok(decoder.decode(), "the bad order decodes");
    let from_orchestra = Validator::new(import.dictionary()).validate(&msg);
    assert!(from_orchestra.is_err());
    assert_eq!(from_orchestra, Validator::new(quickfix()).validate(&msg));
}

#[test]
fn test_orchestra_fix44_session_messages_are_admin() {
    let import = orchestra();
    let admin: BTreeSet<&str> = import
        .dictionary()
        .messages()
        .filter(|message| message.category == MessageCategory::Admin)
        .map(|message| message.msg_type.as_str())
        .collect();
    let expected: BTreeSet<&str> = quickfix()
        .messages()
        .filter(|message| message.category == MessageCategory::Admin)
        .map(|message| message.msg_type.as_str())
        .collect();
    assert_eq!(admin, expected);
    assert!(admin.contains("A") && admin.contains("0") && admin.contains("5"));
}
