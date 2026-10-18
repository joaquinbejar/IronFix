/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Proves the repeating-group reader allocates nothing on the read path.
//!
//! `dhat` is installed as this binary's global allocator and counts every
//! heap block. The dictionary, the [`MessageLayout`], the frames and the
//! decoded messages are built first. Inside the measured window the test:
//!
//! - reads a group (which checks the whole instance), iterates its entries,
//!   walks each entry's fields, looks fields up, and reads and iterates a
//!   nested group;
//! - reads a group positioned after another top-level group, so the walk
//!   skips the first group's run to reach it;
//! - reads an absent group;
//! - iterates the layout's top-level groups;
//! - reads a malformed group, which fails with a count mismatch;
//! - repeats the first read through a static [`GroupSet`];
//! - looks message-level fields up past both groups with
//!   [`GroupSet::field`], through the layout and the static set, including a
//!   tag that appears only inside a group entry.
//!
//! The number of blocks allocated in the window must be zero.
//!
//! It runs without the libtest harness (`harness = false` in `Cargo.toml`), so
//! no other test and no harness thread allocates while it measures. It
//! asserts counts, never timings, and holds in debug and release builds.

use ironfix_dictionary::{
    Dictionary, GroupEntries, GroupError, GroupSet, GroupSpec, MessageLayout,
};
use ironfix_tagvalue::Decoder;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

/// FIX 4.4 NoPartySubIDs(802) and NoPartyIDs(453), as generated code would
/// write them.
const SUB_IDS: GroupSpec<'static> = match GroupSpec::new(802, 523, &[523, 803], &[]) {
    Ok(spec) => spec,
    Err(_) => panic!("bad NoPartySubIDs table"),
};
const PARTIES: GroupSpec<'static> =
    match GroupSpec::new(453, 448, &[447, 448, 452, 802], &[SUB_IDS]) {
        Ok(spec) => spec,
        Err(_) => panic!("bad NoPartyIDs table"),
    };
const ORDER_GROUPS: GroupSet<'static> = match GroupSet::new(&[PARTIES]) {
    Ok(set) => set,
    Err(_) => panic!("bad NewOrderSingle group table"),
};

/// What a walk over the parties saw.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    /// PartyID and PartySubID values found.
    values: usize,
    /// Their total length, in bytes.
    bytes: usize,
    /// Fields of the party entries, nested ones included.
    fields: usize,
}

/// Walks every party and sub-ID of `parties`.
fn walk_parties(parties: GroupEntries<'_, '_, '_>) -> Seen {
    let mut seen = Seen {
        values: 0,
        bytes: 0,
        fields: 0,
    };
    for party in parties {
        seen.fields += party.fields().len();
        if let Some(id) = party.get(448) {
            seen.values += 1;
            seen.bytes += id.value.len();
        }
        if let Ok(Some(sub_ids)) = party.group(802) {
            for sub_id in sub_ids {
                if let Some(value) = sub_id.get(523) {
                    seen.values += 1;
                    seen.bytes += value.value.len();
                }
            }
        }
    }
    seen
}

/// Builds a NewOrderSingle frame around `groups`, with a BodyLength (9) that
/// matches it.
fn frame(groups: &str) -> String {
    let body = format!(
        "35=D\x0149=S\x0156=T\x0134=1\x0152=20260712-10:00:00\x0111=ORDER-1\x01{groups}\
         55=EURUSD\x0154=1\x0160=20260712-10:00:00\x0140=1\x01"
    );
    format!("8=FIX.4.4\x019={}\x01{body}10=000\x01", body.len())
}

fn main() {
    let dict = match Dictionary::fix44() {
        Ok(dict) => dict,
        Err(err) => panic!("the embedded FIX 4.4 dictionary must load: {err}"),
    };
    let layout = match MessageLayout::new(dict, "D") {
        Ok(layout) => layout,
        Err(err) => panic!("the NewOrderSingle layout must build: {err}"),
    };
    // Three parties (the first with two sub-IDs), then two trading sessions.
    let good = frame(
        "453=3\x01448=BROKER-A\x01447=D\x01452=1\x01802=2\x01523=SUB-1\x01803=1\x01\
         523=SUB-2\x01803=2\x01448=BROKER-B\x01447=D\x01452=3\x01448=BROKER-C\x01\
         386=2\x01336=SESSION-A\x01336=SESSION-B\x01",
    );
    // Declares three parties and carries two.
    let bad = frame("453=3\x01448=BROKER-A\x01448=BROKER-B\x01");
    let mut decoder = Decoder::new(good.as_bytes()).with_checksum_validation(false);
    let msg = match decoder.decode() {
        Ok(msg) => msg,
        Err(err) => panic!("the good frame must decode: {err}"),
    };
    let mut decoder = Decoder::new(bad.as_bytes()).with_checksum_validation(false);
    let malformed = match decoder.decode() {
        Ok(msg) => msg,
        Err(err) => panic!("the malformed frame must decode: {err}"),
    };

    let profiler = dhat::Profiler::builder().testing().build();
    let before = dhat::HeapStats::get();

    let from_layout = match layout.read(&msg, 453) {
        Ok(Some(parties)) => walk_parties(parties),
        other => panic!("NoPartyIDs must read through the layout: {other:?}"),
    };
    let sessions = match layout.read(&msg, 386) {
        Ok(Some(sessions)) => sessions.filter(|entry| entry.get(336).is_some()).count(),
        other => panic!("NoTradingSessions must read after NoPartyIDs: {other:?}"),
    };
    let absent = matches!(layout.read(&msg, 78), Ok(None));
    let top_level = layout
        .groups()
        .iter()
        .filter(|spec| spec.count_tag() == 453 || spec.count_tag() == 386)
        .count();
    let mismatch = matches!(
        layout.read(&malformed, 453),
        Err(GroupError::CountMismatch {
            count_tag: 453,
            declared: 3,
            actual: 2,
        })
    );
    let from_static = match ORDER_GROUPS.read(&msg, 453) {
        Ok(Some(parties)) => walk_parties(parties),
        other => panic!("NoPartyIDs must read through the static set: {other:?}"),
    };
    let symbol = layout.groups().field(&msg, 55).map(|field| field.value);
    let static_symbol = ORDER_GROUPS.field(&msg, 55).map(|field| field.value);
    let party_at_top = layout.groups().field(&msg, 448).is_some();

    let after = dhat::HeapStats::get();
    drop(profiler);

    assert_eq!(
        after.total_blocks,
        before.total_blocks,
        "reading and iterating groups allocated {} block(s) ({} bytes)",
        after.total_blocks - before.total_blocks,
        after.total_bytes - before.total_bytes
    );
    // Three party IDs and two sub-IDs, over 12 party-entry fields, the same
    // through both paths.
    assert_eq!(
        from_layout,
        Seen {
            values: 5,
            bytes: 34,
            fields: 12,
        }
    );
    assert_eq!(from_static, from_layout);
    assert_eq!(sessions, 2);
    assert!(absent, "NoAllocs(78) is absent from the message");
    assert_eq!(top_level, 2);
    assert!(mismatch, "the malformed NoPartyIDs is a count mismatch");
    assert_eq!(symbol, Some(&b"EURUSD"[..]));
    assert_eq!(static_symbol, symbol);
    assert!(!party_at_top, "PartyID(448) appears only inside NoPartyIDs");
}
