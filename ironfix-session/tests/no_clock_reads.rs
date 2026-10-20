/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! Guard for ADR-0002's time source contract: `ironfix-session` never reads a
//! clock.
//!
//! Every non-test source file of the crate is scanned for the ways Rust code
//! reads time. Test modules (everything from the first `#[cfg(test)]` on) are
//! exempt, because a test needs one real instant to offset synthetic ones
//! from. A new source file must be added to [`SOURCES`]; the companion test
//! fails if `src/` holds a file the list does not cover.

/// Every source file of the crate, embedded at compile time.
const SOURCES: &[(&str, &str)] = &[
    ("lib.rs", include_str!("../src/lib.rs")),
    ("config.rs", include_str!("../src/config.rs")),
    ("heartbeat.rs", include_str!("../src/heartbeat.rs")),
    ("logout.rs", include_str!("../src/logout.rs")),
    ("replay.rs", include_str!("../src/replay.rs")),
    ("sans_io.rs", include_str!("../src/sans_io.rs")),
    ("sequence.rs", include_str!("../src/sequence.rs")),
    ("state.rs", include_str!("../src/state.rs")),
];

/// Expressions that read a clock.
const CLOCK_READS: &[&str] = &[
    "Instant::now",
    "SystemTime::now",
    ".elapsed()",
    "Utc::now",
    "Local::now",
    "Timestamp::now",
    "tokio::time",
];

/// The part of a source file outside its test module.
fn non_test_part(source: &str) -> &str {
    match source.find("#[cfg(test)]") {
        Some(at) => &source[..at],
        None => source,
    }
}

#[test]
fn session_sources_never_read_a_clock() {
    let mut offences = Vec::new();
    for (file, source) in SOURCES {
        for (index, line) in non_test_part(source).lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            for pattern in CLOCK_READS {
                if code.contains(pattern) {
                    offences.push(format!("src/{file}:{}: {}", index + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        offences.is_empty(),
        "ironfix-session must take time as an input (ADR-0002); clock reads found:\n{}",
        offences.join("\n")
    );
}

#[test]
fn guard_covers_every_source_file() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) => panic!("cannot list {}: {err}", dir.display()),
    };
    for entry in entries {
        let name = match entry {
            Ok(entry) => entry.file_name().to_string_lossy().into_owned(),
            Err(err) => panic!("cannot read an entry of {}: {err}", dir.display()),
        };
        assert!(
            SOURCES.iter().any(|(file, _)| *file == name),
            "src/{name} is not scanned by the clock-read guard; add it to SOURCES"
        );
    }
}
