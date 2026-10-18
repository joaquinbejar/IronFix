/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Measures the heap the Orchestra loader needs at its limits.
//!
//! `dhat` is installed as this binary's global allocator. Each case builds a
//! small hostile repository, loads it, and checks the peak heap (`max_bytes`,
//! the highest live total since the profiler started) against a bound; the
//! cases run from the smallest expected peak to the largest, so each check
//! covers the cases before it:
//!
//! 1. a flood of unmapped elements, stopped at
//!    [`MAX_ORCHESTRA_REPORT_ENTRIES`] with a typed error;
//! 2. group references doubling at every level past [`MAX_ORCHESTRA_MEMBERS`],
//!    with a leaf field name at [`MAX_ORCHESTRA_NAME_LEN`], stopped with a
//!    typed error;
//! 3. a full report whose every entry carries the longest location the name
//!    limit allows;
//! 4. one code set of 4 096 codes, each named as long as the name limit
//!    allows, named by 2 048 fields, each of which holds its own copy of the
//!    values: stopped at [`MAX_ORCHESTRA_FIELD_VALUES`] with a typed error;
//! 5. the doubling just under the member limit, which loads.
//!
//! Before the name, report and field-value limits, a review measured
//! documents of 18 KB to 16 MB at 340 MB to 556 MB of resident memory, and
//! the shared code set would copy over 2 GB of names. The bounds below are
//! about twice the peaks measured on aarch64-apple-darwin; they fail on a
//! regression of that kind, not on allocator noise. Every document stays
//! under 4 MB.
//!
//! It runs without the libtest harness (`harness = false` in `Cargo.toml`),
//! so no other test allocates while it measures. It asserts byte counts,
//! never timings.

use ironfix_dictionary::{
    Dictionary, DictionaryError, MAX_ORCHESTRA_FIELD_VALUES, MAX_ORCHESTRA_MEMBERS,
    MAX_ORCHESTRA_NAME_LEN, MAX_ORCHESTRA_REPORT_ENTRIES, ORCHESTRA_NAMESPACE,
};

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

const MIB: usize = 1024 * 1024;

// Bounds on the peak heap, about twice the peaks measured on
// aarch64-apple-darwin (in the comments).
/// Peak after the flood: 7.0 MiB measured.
const BOUND_FLOOD: usize = 16 * MIB;
/// Peak after expansion past the member limit: 36.8 MiB measured.
const BOUND_OVER_BUDGET: usize = 80 * MIB;
/// Peak after the full report: 39.1 MiB measured.
const BOUND_FULL_REPORT: usize = 80 * MIB;
/// Peak after the shared code set: 47.6 MiB measured.
const BOUND_SHARED_CODE_SET: usize = 96 * MIB;
/// Peak after expansion under the member limit: 87.6 MiB measured.
const BOUND_UNDER_BUDGET: usize = 192 * MIB;

/// A repository with the given fields, groups and messages.
fn repository(fields: &str, groups: &str, messages: &str) -> String {
    format!(
        r#"<fixr:repository xmlns:fixr="{ORCHESTRA_NAMESPACE}" name="FIX.4.4" version="FIX.4.4">
  <fixr:datatypes>
    <fixr:datatype name="String"/><fixr:datatype name="NumInGroup"/>
  </fixr:datatypes>
  <fixr:fields>
    <fixr:field id="11" name="ClOrdID" type="String"/>{fields}
  </fixr:fields>
  <fixr:groups>{groups}</fixr:groups>
  <fixr:messages>{messages}</fixr:messages>
</fixr:repository>"#
    )
}

/// `levels` groups, each referencing the next twice, the last holding a
/// field whose name is as long as the loader allows; a message holds the
/// first. The members this expands to: `3 * 2^(levels - 1)`.
fn doubling(levels: u32) -> String {
    let leaf = "L".repeat(MAX_ORCHESTRA_NAME_LEN);
    let mut fields = format!(r#"<fixr:field id="7000" name="{leaf}" type="String"/>"#);
    let mut groups = String::new();
    for level in 0..levels {
        let count = 6000 + level;
        fields.push_str(&format!(
            r#"<fixr:field id="{count}" name="NoLevel{level}" type="NumInGroup"/>"#
        ));
        let members = if level + 1 == levels {
            r#"<fixr:fieldRef id="7000"/>"#.to_owned()
        } else {
            format!(r#"<fixr:groupRef id="{}"/>"#, 2101 + level).repeat(2)
        };
        groups.push_str(&format!(
            r#"<fixr:group id="{}" name="Level{level}"><fixr:numInGroup id="{count}"/>{members}</fixr:group>"#,
            2100 + level
        ));
    }
    repository(
        &fields,
        &groups,
        r#"<fixr:message id="1" name="Deep" msgType="U9"><fixr:structure><fixr:groupRef id="2100"/></fixr:structure></fixr:message>"#,
    )
}

/// One code set of `codes` codes, each named as long as the loader allows,
/// named by `fields` fields: every field holds its own copy of the values,
/// `codes * fields` of them in all.
fn shared_code_set(codes: u32, fields: u32) -> String {
    let name = "N".repeat(MAX_ORCHESTRA_NAME_LEN);
    let codes: String = (0..codes)
        .map(|i| format!(r#"<fixr:code id="{}" name="{name}" value="{i}"/>"#, i + 1))
        .collect();
    let fields: String = (0..fields)
        .map(|i| {
            format!(
                r#"<fixr:field id="{}" name="F{i}" type="WideCodeSet"/>"#,
                i + 1
            )
        })
        .collect();
    format!(
        r#"<fixr:repository xmlns:fixr="{ORCHESTRA_NAMESPACE}" name="FIX.4.4" version="FIX.4.4">
  <fixr:datatypes><fixr:datatype name="String"/></fixr:datatypes>
  <fixr:codeSets><fixr:codeSet id="1" name="WideCodeSet" type="String">{codes}</fixr:codeSet></fixr:codeSets>
  <fixr:fields>{fields}</fixr:fields>
  <fixr:messages/>
</fixr:repository>"#
    )
}

/// Checks the peak heap so far against `bound` bytes.
#[track_caller]
fn assert_peak(bound: usize, case: &str) {
    let peak = dhat::HeapStats::get().max_bytes;
    assert!(
        peak <= bound,
        "{case}: the peak heap is {peak} bytes, over the {bound}-byte bound"
    );
}

fn main() {
    // Built before the profiler starts: only loading is measured.
    let flood = repository(&"<fixr:x/>".repeat(3 * MIB / 9), "", "");
    let long_message = "M".repeat(MAX_ORCHESTRA_NAME_LEN);
    let ignored =
        r#"<fixr:fieldRef id="11" presence="ignored"/>"#.repeat(MAX_ORCHESTRA_REPORT_ENTRIES - 1);
    let full_report = repository(
        "",
        "",
        &format!(
            r#"<fixr:message id="1" name="{long_message}" msgType="U1"><fixr:structure>{ignored}</fixr:structure></fixr:message>"#
        ),
    );
    let over_budget = doubling(18);
    let under_budget = doubling(17);
    // 4 096 codes named by 2 048 fields: 8 388 608 copies of 255-byte names
    // without the limit.
    let shared = shared_code_set(4096, 2048);
    for document in [&flood, &full_report, &over_budget, &under_budget, &shared] {
        assert!(document.len() < 4 * MIB);
    }

    let _profiler = dhat::Profiler::builder().testing().build();

    assert_eq!(
        Dictionary::from_orchestra_xml(&flood).err(),
        Some(DictionaryError::TooManyUnmapped {
            limit: MAX_ORCHESTRA_REPORT_ENTRIES,
        })
    );
    assert_peak(BOUND_FLOOD, "a flood of unmapped elements");

    assert_eq!(
        Dictionary::from_orchestra_xml(&over_budget).err(),
        Some(DictionaryError::TooManyMembers {
            limit: MAX_ORCHESTRA_MEMBERS,
        })
    );
    assert_peak(BOUND_OVER_BUDGET, "group expansion past the member limit");

    let report = match Dictionary::from_orchestra_xml(&full_report) {
        Ok(import) => import.report().len(),
        Err(err) => panic!("a full report must load: {err}"),
    };
    assert_eq!(report, MAX_ORCHESTRA_REPORT_ENTRIES - 1);
    assert_peak(BOUND_FULL_REPORT, "a full report of long locations");

    assert_eq!(
        Dictionary::from_orchestra_xml(&shared).err(),
        Some(DictionaryError::TooManyFieldValues {
            limit: MAX_ORCHESTRA_FIELD_VALUES,
        })
    );
    assert_peak(BOUND_SHARED_CODE_SET, "a code set shared by many fields");

    match Dictionary::from_orchestra_xml(&under_budget) {
        Ok(import) => assert!(import.dictionary().get_message("U9").is_some()),
        Err(err) => panic!("expansion under the member limit must load: {err}"),
    }
    assert_peak(BOUND_UNDER_BUDGET, "group expansion under the member limit");
}
