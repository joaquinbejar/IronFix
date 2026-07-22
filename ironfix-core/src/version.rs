/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! FIX protocol versions and their on-the-wire representation.
//!
//! [`FixVersion`] is the **single** place in the workspace that maps a FIX
//! version to the two values that carry it on the wire: `BeginString` (tag 8)
//! and, for the 5.0 family, the application version stamped into
//! `DefaultApplVerID` (1137) on the Logon and `ApplVerID` (1128) on
//! application messages.
//!
//! It lives in `ironfix-core` because two crates need the same answer and
//! neither may depend on the other: `ironfix-dictionary` re-exports it as
//! `Version` for schema loading, and `ironfix-engine` uses it to stamp the
//! standard header. `ironfix-engine` must not depend on `ironfix-dictionary`
//! (a hard DAG invariant, see `CLAUDE.md`), so before this type existed the
//! table was duplicated in both and could drift apart untested.
//!
//! ## The FIXT.1.1 split
//!
//! FIX 5.0 separates the transport (session) version from the application
//! version. A 5.0 session is framed as a FIXT.1.1 session — `BeginString` is
//! always `FIXT.1.1` — and the application version travels in 1137 / 1128
//! (FIXT 1.1 specification, "Standard Message Header"; see also
//! `doc/fix_operations.md`, "FIX 5.0 / FIXT.1.1"). Putting `FIX.5.0*` in tag 8
//! is rejected outright by conforming counterparties.
//!
//! Consequently [`FixVersion::as_str`] (the version's own name, e.g.
//! `FIX.5.0SP2`) and [`FixVersion::begin_string`] (what goes in tag 8, e.g.
//! `FIXT.1.1`) are different questions and must not be confused.

use crate::error::UnknownFixVersion;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A FIX protocol version.
///
/// The canonical name of a variant is [`FixVersion::as_str`], which is also
/// the string [`FromStr`] accepts. Its wire framing is
/// [`FixVersion::begin_string`] plus [`FixVersion::appl_ver_id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FixVersion {
    /// FIX 4.0
    Fix40,
    /// FIX 4.1
    Fix41,
    /// FIX 4.2
    Fix42,
    /// FIX 4.3
    Fix43,
    /// FIX 4.4
    Fix44,
    /// FIX 5.0, framed as a FIXT.1.1 session.
    Fix50,
    /// FIX 5.0 SP1, framed as a FIXT.1.1 session.
    Fix50Sp1,
    /// FIX 5.0 SP2, framed as a FIXT.1.1 session.
    Fix50Sp2,
    /// FIXT 1.1, the transport version used by FIX 5.0 and later.
    ///
    /// On its own it names no application version, so it has no
    /// [`FixVersion::appl_ver_id`]: a session that must stamp
    /// `DefaultApplVerID` (1137) cannot be described by this variant alone.
    Fixt11,
}

impl FixVersion {
    /// Every version this workspace knows, in ascending order.
    ///
    /// Iterating this is the way to assert the version mapping exhaustively
    /// from a single place, rather than restating the table in a consumer.
    pub const ALL: [Self; 9] = [
        Self::Fix40,
        Self::Fix41,
        Self::Fix42,
        Self::Fix43,
        Self::Fix44,
        Self::Fix50,
        Self::Fix50Sp1,
        Self::Fix50Sp2,
        Self::Fixt11,
    ];

    /// Returns the version's canonical name, e.g. `FIX.5.0SP2`.
    ///
    /// This is the version's own identity — the string a session is
    /// configured with and the string [`FromStr`] parses. For the 5.0 family
    /// it is **not** what goes in `BeginString`; see
    /// [`FixVersion::begin_string`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fix40 => "FIX.4.0",
            Self::Fix41 => "FIX.4.1",
            Self::Fix42 => "FIX.4.2",
            Self::Fix43 => "FIX.4.3",
            Self::Fix44 => "FIX.4.4",
            Self::Fix50 => "FIX.5.0",
            Self::Fix50Sp1 => "FIX.5.0SP1",
            Self::Fix50Sp2 => "FIX.5.0SP2",
            Self::Fixt11 => "FIXT.1.1",
        }
    }

    /// Returns the value stamped into `BeginString` (tag 8).
    ///
    /// Pre-5.0 versions carry their own name. FIX 5.0 and later are framed as
    /// FIXT.1.1 sessions and carry `FIXT.1.1`, with the application version
    /// in 1137 / 1128 instead.
    #[must_use]
    pub const fn begin_string(self) -> &'static str {
        match self {
            Self::Fix40 => "FIX.4.0",
            Self::Fix41 => "FIX.4.1",
            Self::Fix42 => "FIX.4.2",
            Self::Fix43 => "FIX.4.3",
            Self::Fix44 => "FIX.4.4",
            Self::Fix50 | Self::Fix50Sp1 | Self::Fix50Sp2 | Self::Fixt11 => "FIXT.1.1",
        }
    }

    /// Returns the application version to stamp into `DefaultApplVerID`
    /// (1137) on the Logon and `ApplVerID` (1128) on application messages,
    /// or `None` for a session that carries neither field.
    ///
    /// The codes are the `ApplVerID` enumeration: `7` = FIX.5.0,
    /// `8` = FIX.5.0SP1, `9` = FIX.5.0SP2. That enumeration also defines
    /// codes for pre-5.0 versions (`2` = FIX.4.0 … `6` = FIX.4.4), but they
    /// are not returned here: a pre-5.0 session is not a FIXT session and
    /// never carries 1137 or 1128, so the honest answer is `None`.
    ///
    /// [`FixVersion::Fixt11`] is also `None` — it names the transport version
    /// only. A caller that must stamp the **required** 1137 has to reject
    /// that combination rather than guess an application version.
    pub const fn appl_ver_id(self) -> Option<&'static str> {
        match self {
            Self::Fix50 => Some("7"),
            Self::Fix50Sp1 => Some("8"),
            Self::Fix50Sp2 => Some("9"),
            Self::Fix40 | Self::Fix41 | Self::Fix42 | Self::Fix43 | Self::Fix44 | Self::Fixt11 => {
                None
            }
        }
    }

    /// Returns `true` when this version is framed as a FIXT.1.1 session,
    /// i.e. FIX 5.0 and later plus FIXT.1.1 itself.
    #[must_use]
    pub const fn uses_fixt(self) -> bool {
        matches!(
            self,
            Self::Fix50 | Self::Fix50Sp1 | Self::Fix50Sp2 | Self::Fixt11
        )
    }
}

impl fmt::Display for FixVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FixVersion {
    type Err = UnknownFixVersion;

    /// Parses a version's canonical name, e.g. `FIX.4.4` or `FIX.5.0SP2`.
    ///
    /// Matching is exact: FIX version strings travel on the wire verbatim and
    /// are case-sensitive, so a lenient parse here would accept a value that
    /// no counterparty would.
    ///
    /// # Errors
    /// Returns [`UnknownFixVersion`] when the string names no version in
    /// [`FixVersion::ALL`].
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|version| version.as_str() == value)
            .ok_or_else(|| UnknownFixVersion::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one table in the workspace, asserted entry by entry. Both
    /// `ironfix-dictionary` and `ironfix-engine` derive their answer from
    /// these methods, so this covers the mapping for every consumer.
    #[test]
    fn test_fix_version_mapping_is_exhaustive_and_exact() {
        let expected = [
            (FixVersion::Fix40, "FIX.4.0", "FIX.4.0", None, false),
            (FixVersion::Fix41, "FIX.4.1", "FIX.4.1", None, false),
            (FixVersion::Fix42, "FIX.4.2", "FIX.4.2", None, false),
            (FixVersion::Fix43, "FIX.4.3", "FIX.4.3", None, false),
            (FixVersion::Fix44, "FIX.4.4", "FIX.4.4", None, false),
            (FixVersion::Fix50, "FIX.5.0", "FIXT.1.1", Some("7"), true),
            (
                FixVersion::Fix50Sp1,
                "FIX.5.0SP1",
                "FIXT.1.1",
                Some("8"),
                true,
            ),
            (
                FixVersion::Fix50Sp2,
                "FIX.5.0SP2",
                "FIXT.1.1",
                Some("9"),
                true,
            ),
            (FixVersion::Fixt11, "FIXT.1.1", "FIXT.1.1", None, true),
        ];

        assert_eq!(
            expected.len(),
            FixVersion::ALL.len(),
            "every version must be covered"
        );
        for (version, name, begin_string, appl_ver_id, uses_fixt) in expected {
            assert!(
                FixVersion::ALL.contains(&version),
                "{version:?} is missing from FixVersion::ALL"
            );
            assert_eq!(version.as_str(), name);
            assert_eq!(version.begin_string(), begin_string);
            assert_eq!(version.appl_ver_id(), appl_ver_id);
            assert_eq!(version.uses_fixt(), uses_fixt);
        }
    }

    #[test]
    fn test_fix_version_roundtrips_through_its_canonical_name() {
        for version in FixVersion::ALL {
            assert_eq!(version.as_str().parse(), Ok(version));
            assert_eq!(version.to_string(), version.as_str());
        }
    }

    #[test]
    fn test_fix_version_names_are_unique() {
        for (index, version) in FixVersion::ALL.into_iter().enumerate() {
            let duplicates = FixVersion::ALL
                .into_iter()
                .enumerate()
                .filter(|(other_index, other)| {
                    *other_index != index && other.as_str() == version.as_str()
                })
                .count();
            assert_eq!(duplicates, 0, "{version:?} shares its name with another");
        }
    }

    #[test]
    fn test_fix_version_from_str_unknown_is_typed_error() {
        match "FIX.9.9".parse::<FixVersion>() {
            Err(err) => assert_eq!(err.value(), "FIX.9.9"),
            Ok(version) => unreachable!("FIX.9.9 is not a version, got {version:?}"),
        }
    }

    #[test]
    fn test_fix_version_from_str_is_case_sensitive() {
        assert!("fix.4.4".parse::<FixVersion>().is_err());
        assert!("FIX.5.0sp2".parse::<FixVersion>().is_err());
    }

    #[test]
    fn test_fix_version_only_fifty_family_carries_appl_ver_id() {
        for version in FixVersion::ALL {
            if version.appl_ver_id().is_some() {
                assert!(
                    version.uses_fixt(),
                    "{version:?} stamps an ApplVerID but is not a FIXT session"
                );
            }
        }
    }
}
