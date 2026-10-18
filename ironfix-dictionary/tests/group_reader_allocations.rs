/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Proves the repeating-group reader allocates nothing on the read path.
//!
//! `dhat` is installed as this binary's global allocator and counts every
//! heap block. The dictionary, the [`MessageLayout`], the frame and the
//! decoded message are built first; then, inside the measured window, the
//! test reads a group (which checks the whole instance), iterates its
//! entries, looks fields up, reads a nested group and iterates it, reads an
//! absent group, and does the same through a static [`GroupSet`]. The number
//! of blocks allocated in the window must be zero.
//!
//! It runs without the libtest harness (`harness = false` in `Cargo.toml`), so
//! no other test and no harness thread allocates while it measures. It
//! asserts counts, never timings.

use ironfix_dictionary::{Dictionary, GroupEntries, GroupSet, GroupSpec, MessageLayout};
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

/// Walks every party and sub-ID of `parties`, returning how many values were
/// seen and their total length in bytes.
fn walk_parties(parties: GroupEntries<'_, '_, '_>) -> (usize, usize) {
    let mut seen = 0;
    let mut bytes = 0;
    for party in parties {
        if let Some(id) = party.get(448) {
            seen += 1;
            bytes += id.value.len();
        }
        if let Ok(Some(sub_ids)) = party.group(802) {
            for sub_id in sub_ids {
                if let Some(value) = sub_id.get(523) {
                    seen += 1;
                    bytes += value.value.len();
                }
            }
        }
    }
    (seen, bytes)
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
    let body = "35=D\x0149=S\x0156=T\x0134=1\x0152=20260712-10:00:00\x0111=ORDER-1\x01\
                453=3\x01448=BROKER-A\x01447=D\x01452=1\x01802=2\x01523=SUB-1\x01803=1\x01\
                523=SUB-2\x01803=2\x01448=BROKER-B\x01447=D\x01452=3\x01448=BROKER-C\x01\
                55=EURUSD\x0154=1\x0160=20260712-10:00:00\x0140=1\x01";
    let frame = format!("8=FIX.4.4\x019={}\x01{body}10=000\x01", body.len());
    let mut decoder = Decoder::new(frame.as_bytes()).with_checksum_validation(false);
    let msg = match decoder.decode() {
        Ok(msg) => msg,
        Err(err) => panic!("the test frame must decode: {err}"),
    };

    let profiler = dhat::Profiler::builder().testing().build();
    let before = dhat::HeapStats::get();

    let from_layout = match layout.read(&msg, 453) {
        Ok(Some(parties)) => walk_parties(parties),
        other => panic!("NoPartyIDs must read through the layout: {other:?}"),
    };
    let absent = matches!(layout.read(&msg, 78), Ok(None));
    let from_static = match ORDER_GROUPS.read(&msg, 453) {
        Ok(Some(parties)) => walk_parties(parties),
        other => panic!("NoPartyIDs must read through the static set: {other:?}"),
    };

    let after = dhat::HeapStats::get();
    drop(profiler);

    assert_eq!(
        after.total_blocks,
        before.total_blocks,
        "reading and iterating groups allocated {} block(s) ({} bytes)",
        after.total_blocks - before.total_blocks,
        after.total_bytes - before.total_bytes
    );
    // Three party IDs and two sub-IDs, the same through both paths.
    assert_eq!(from_layout, (5, 34));
    assert_eq!(from_static, from_layout);
    assert!(absent, "NoAllocs(78) is absent from the message");
}
