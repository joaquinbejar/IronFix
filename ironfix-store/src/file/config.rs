/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Configuration of a [`FileStore`](super::FileStore): where its files live,
//! what they are called, how large a frame may be, and when the journal is
//! flushed to stable storage.

use crate::file::format::DamageRule;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Largest frame a [`FileStore`](super::FileStore) accepts unless configured
/// otherwise, in bytes (1 MiB).
///
/// The same figure as the session layer's default `max_message_size`, so a
/// frame the engine is willing to build is a frame the store is willing to
/// file. The two are not linked: `ironfix-store` does not depend on
/// `ironfix-session`.
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 1024 * 1024;

/// Largest value [`FileStoreConfig::with_max_frame_size`] accepts, in bytes
/// (64 MiB).
///
/// The bound is also the largest allocation reading one journal record can
/// make, whatever the journal claims.
pub const MAX_FRAME_SIZE_LIMIT: u32 = 64 * 1024 * 1024;

/// Longest store name [`FileStoreConfig::try_new`] accepts, in bytes.
///
/// The name becomes a file name with a suffix of at most 12 bytes, and common
/// file systems cap a file name at 255 bytes.
pub const MAX_STORE_NAME_LEN: usize = 128;

/// Device names Windows reserves in every directory, with or without an
/// extension. A store name whose first dot-separated part is one of them,
/// in any case, is refused, so a store's files can be created on Windows.
const WINDOWS_RESERVED_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// [`DEFAULT_MAX_FRAME_SIZE`] as the type the configuration holds, resolved at
/// compile time.
const DEFAULT_MAX_FRAME: NonZeroU32 = match NonZeroU32::new(DEFAULT_MAX_FRAME_SIZE) {
    Some(size) => size,
    None => NonZeroU32::MIN,
};

/// When a [`FileStore`](super::FileStore) flushes its journal to stable
/// storage.
///
/// Every write reaches the operating system (a `write` system call) before the
/// store call returns, under every policy, so a write that returned `Ok`
/// survives the **process** crashing. The policy decides what survives the
/// **operating system** crashing or the machine losing power, which is what a
/// flush ([`std::fs::File::sync_data`]; on Apple platforms the standard
/// library implements it with `F_FULLFSYNC`) protects against. See
/// `doc/adr/0006-file-store.md` for what each policy guarantees against the
/// crash points of issue #89. What a flush costs is not measured here:
/// `ironfix-store/benches/file_store.rs` exercises it, and no figure is
/// published.
///
/// Whatever the policy, a reset
/// ([`MessageStore::reset`](crate::MessageStore::reset),
/// [`MessageStore::reset_to`](crate::MessageStore::reset_to)) and the creation
/// of a new journal flush the new file before renaming it into place and the
/// directory after, so an operating-system crash never undoes a reset.
///
/// The policy also decides how much damage at the end of the journal
/// [`FileStore::open`](super::FileStore::open) accepts as an interrupted
/// write, so open a journal with the policy it was written under.
///
/// These guarantees are stated for Unix. Elsewhere the directory is not
/// flushed, and the store is untested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SyncPolicy {
    /// Flush after every journal write, before the call returns `Ok`.
    ///
    /// The engine writes the store once per outbound message and once per
    /// inbound message (the receive cursor), so this is one flush per message
    /// in each direction. The only policy under which a write that returned
    /// `Ok` survives an operating-system crash or a power loss, and so the
    /// only one that turns the engine's write order into a guarantee against
    /// them. The default.
    #[default]
    EveryWrite,
    /// Flush after every `n`-th journal write.
    ///
    /// On an operating-system crash or a power loss, up to `n - 1` writes that
    /// returned `Ok` can be lost, together with the write in flight. A lost
    /// write can be a frame the counterparty already received and the sender
    /// counter that numbered it, so the next session can reuse a `MsgSeqNum`
    /// (34) with different content. There is **no time bound**: on a quiet
    /// session the last writes stay unflushed until `n` accumulate, the store
    /// is refreshed or closed, or [`FileStore::sync`](super::FileStore::sync)
    /// is called (the engine never calls it). `EveryN(1)` behaves as
    /// [`SyncPolicy::EveryWrite`].
    EveryN(NonZeroU32),
    /// Never flush the journal's writes, except through an explicit
    /// [`FileStore::sync`](super::FileStore::sync), which the engine never
    /// calls.
    ///
    /// Survives a process crash only. On an operating-system crash or a power
    /// loss any number of writes that returned `Ok` can be lost, and damage
    /// anywhere in the journal is cut at the next open rather than refused.
    Never,
}

impl SyncPolicy {
    /// Whether the journal is flushed when it is opened, refreshed or cut.
    #[must_use]
    pub(crate) const fn flushes(self) -> bool {
        !matches!(self, Self::Never)
    }

    /// Which damage a journal written under this policy may be cut at when it
    /// is opened: what an interrupted write can leave, given how many writes
    /// the policy leaves unflushed.
    #[must_use]
    pub(crate) const fn damage_rule(self) -> DamageRule {
        match self {
            Self::EveryWrite => DamageRule::Tail { records: 1 },
            Self::EveryN(every) => DamageRule::Tail {
                records: every.get() as u64,
            },
            Self::Never => DamageRule::Anywhere,
        }
    }
}

/// Rejected [`FileStoreConfig`] values.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileStoreConfigError {
    /// The store name is empty.
    #[error("store name is empty")]
    EmptyName,

    /// The store name is longer than [`MAX_STORE_NAME_LEN`].
    #[error("store name is {len} bytes long; at most {max} are allowed")]
    NameTooLong {
        /// Length of the rejected name, in bytes.
        len: usize,
        /// The limit, [`MAX_STORE_NAME_LEN`].
        max: usize,
    },

    /// The store name contains a character that is not allowed in it.
    ///
    /// The name becomes part of a file name, so only ASCII letters, digits,
    /// `.`, `-` and `_` are accepted: no path separator, no space, nothing a
    /// file system might treat specially.
    #[error(
        "store name contains {character:?}; only ASCII letters, digits, '.', '-' and '_' are allowed"
    )]
    IllegalCharacter {
        /// The first rejected character.
        character: char,
    },

    /// The store name starts with `.`, which would make its files hidden on
    /// Unix and lets `.` and `..` read as directory references.
    #[error("store name must not start with '.'")]
    LeadingDot,

    /// The store name is, before its first `.`, a device name Windows
    /// reserves (`CON`, `PRN`, `AUX`, `NUL`, `COM1` to `COM9`, `LPT1` to
    /// `LPT9`, in any case).
    #[error("store name {name:?} is a device name Windows reserves")]
    ReservedName {
        /// The rejected name.
        name: String,
    },

    /// The maximum frame size is above [`MAX_FRAME_SIZE_LIMIT`].
    #[error("max frame size of {size} bytes is above the {max}-byte limit")]
    MaxFrameSizeTooLarge {
        /// The rejected size, in bytes.
        size: u32,
        /// The limit, [`MAX_FRAME_SIZE_LIMIT`].
        max: u32,
    },
}

/// Where a [`FileStore`](super::FileStore) keeps its files and how it writes
/// them.
///
/// A store is three files in [`directory`](Self::directory), all named after
/// the store's [`name`](Self::name):
///
/// - `<name>.journal`: the message journal and the sequence counters;
/// - `<name>.journal.tmp`: a replacement journal while a reset is being
///   written, removed at the next open if a crash left it behind;
/// - `<name>.lock`: held locked while the store is open, so a second store on
///   the same files fails to open instead of interleaving two sequence
///   streams.
///
/// Name each session's store differently (for example after its
/// `BeginString` and CompIDs) when several share a directory, and treat names
/// as **case-insensitive**: on a case-insensitive file system (the default on
/// macOS and Windows) two names that differ only in case are the same files.
/// The lock then refuses the second store while the first is open, but two
/// sessions opened one after the other would share one journal.
///
/// A missing journal is an error unless
/// [`with_create_if_missing`](Self::with_create_if_missing) is set, so a
/// store that was expected to exist (a wrong directory, an unmounted volume)
/// is never silently replaced by a fresh one at 1/1.
///
/// Valid by construction: the fields are private and every constructor and
/// setter that can receive an invalid value validates it.
///
/// # Example
///
/// ```
/// use ironfix_store::{FileStoreConfig, SyncPolicy};
/// use std::num::NonZeroU32;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = FileStoreConfig::try_new("/var/lib/ironfix", "FIX.4.4-CLIENT-VENUE")?
///     .with_create_if_missing(true)
///     .with_sync_policy(SyncPolicy::EveryN(NonZeroU32::new(16).ok_or("zero")?))
///     .with_max_frame_size(NonZeroU32::new(256 * 1024).ok_or("zero")?)?;
/// assert_eq!(config.name(), "FIX.4.4-CLIENT-VENUE");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStoreConfig {
    /// Directory holding the store's files.
    directory: PathBuf,
    /// File-name-safe store name.
    name: String,
    /// When the journal is flushed.
    sync_policy: SyncPolicy,
    /// Largest frame accepted, in bytes.
    max_frame_size: NonZeroU32,
    /// Whether opening creates the directory and an empty journal when they
    /// are missing.
    create_if_missing: bool,
}

impl FileStoreConfig {
    /// Creates a configuration for the store `name` in `directory`, with
    /// [`SyncPolicy::EveryWrite`], [`DEFAULT_MAX_FRAME_SIZE`], and
    /// `create_if_missing` off.
    ///
    /// # Arguments
    /// * `directory` - Directory for the store's files
    /// * `name` - The store's name, used in its file names: 1 to
    ///   [`MAX_STORE_NAME_LEN`] bytes of ASCII letters, digits, `.`, `-` and
    ///   `_`, not starting with `.` and not a Windows device name
    ///
    /// # Errors
    /// [`FileStoreConfigError::EmptyName`],
    /// [`FileStoreConfigError::NameTooLong`],
    /// [`FileStoreConfigError::IllegalCharacter`],
    /// [`FileStoreConfigError::LeadingDot`] or
    /// [`FileStoreConfigError::ReservedName`] for a name that cannot be used
    /// as part of a file name.
    pub fn try_new(
        directory: impl Into<PathBuf>,
        name: impl Into<String>,
    ) -> Result<Self, FileStoreConfigError> {
        let name = name.into();
        validate_name(&name)?;
        Ok(Self {
            directory: directory.into(),
            name,
            sync_policy: SyncPolicy::default(),
            max_frame_size: DEFAULT_MAX_FRAME,
            create_if_missing: false,
        })
    }

    /// Sets whether [`FileStore::open`](super::FileStore::open) creates the
    /// directory (flushing each directory it creates into its parent) and an
    /// empty journal, with both counters at 1, when they are missing (default
    /// `false`: a missing journal is an error).
    #[must_use = "builders do nothing unless the result is used"]
    pub const fn with_create_if_missing(mut self, create: bool) -> Self {
        self.create_if_missing = create;
        self
    }

    /// Sets when the journal is flushed (default [`SyncPolicy::EveryWrite`]).
    #[must_use = "builders do nothing unless the result is used"]
    pub const fn with_sync_policy(mut self, policy: SyncPolicy) -> Self {
        self.sync_policy = policy;
        self
    }

    /// Sets the largest frame the store accepts, in bytes (default
    /// [`DEFAULT_MAX_FRAME_SIZE`], at most [`MAX_FRAME_SIZE_LIMIT`]).
    ///
    /// A frame above it is refused by the write that offers it. The bound also
    /// caps what reading the journal allocates for one record: a journal
    /// record declaring more than this (plus a fixed record overhead) makes
    /// [`FileStore::open`](super::FileStore::open) fail with
    /// `StoreError::Corrupted` rather than allocate it. **Lowering it below
    /// the size of a frame already filed therefore makes the journal
    /// unreadable** until it is raised again.
    ///
    /// # Errors
    /// [`FileStoreConfigError::MaxFrameSizeTooLarge`] above
    /// [`MAX_FRAME_SIZE_LIMIT`].
    pub fn with_max_frame_size(mut self, size: NonZeroU32) -> Result<Self, FileStoreConfigError> {
        if size.get() > MAX_FRAME_SIZE_LIMIT {
            return Err(FileStoreConfigError::MaxFrameSizeTooLarge {
                size: size.get(),
                max: MAX_FRAME_SIZE_LIMIT,
            });
        }
        self.max_frame_size = size;
        Ok(self)
    }

    /// Returns the directory holding the store's files.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Returns the store's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns when the journal is flushed.
    #[must_use]
    pub const fn sync_policy(&self) -> SyncPolicy {
        self.sync_policy
    }

    /// Returns the largest frame the store accepts, in bytes.
    #[must_use]
    pub const fn max_frame_size(&self) -> NonZeroU32 {
        self.max_frame_size
    }

    /// Returns whether opening creates a missing directory and journal.
    #[must_use]
    pub const fn create_if_missing(&self) -> bool {
        self.create_if_missing
    }

    /// Returns the path of the journal, `<directory>/<name>.journal`.
    #[must_use]
    pub fn journal_path(&self) -> PathBuf {
        self.directory.join(format!("{}.journal", self.name))
    }

    /// Returns the path a replacement journal is written to before it is
    /// renamed into place, `<directory>/<name>.journal.tmp`.
    #[must_use]
    pub(crate) fn temp_path(&self) -> PathBuf {
        self.directory.join(format!("{}.journal.tmp", self.name))
    }

    /// Returns the path of the lock file, `<directory>/<name>.lock`.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.directory.join(format!("{}.lock", self.name))
    }
}

/// Checks that `name` can be used as part of a file name.
fn validate_name(name: &str) -> Result<(), FileStoreConfigError> {
    if name.is_empty() {
        return Err(FileStoreConfigError::EmptyName);
    }
    if name.len() > MAX_STORE_NAME_LEN {
        return Err(FileStoreConfigError::NameTooLong {
            len: name.len(),
            max: MAX_STORE_NAME_LEN,
        });
    }
    if let Some(character) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
    {
        return Err(FileStoreConfigError::IllegalCharacter { character });
    }
    if name.starts_with('.') {
        return Err(FileStoreConfigError::LeadingDot);
    }
    let stem = name.split('.').next().unwrap_or(name);
    if WINDOWS_RESERVED_NAMES
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return Err(FileStoreConfigError::ReservedName {
            name: name.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_store_config_try_new_applies_defaults() {
        let config = FileStoreConfig::try_new("/tmp/ironfix", "FIX.4.4-CLIENT_VENUE");
        let Ok(config) = config else {
            panic!("a file-name-safe name must be accepted: {config:?}");
        };
        assert_eq!(config.name(), "FIX.4.4-CLIENT_VENUE");
        assert_eq!(config.directory(), Path::new("/tmp/ironfix"));
        assert_eq!(config.sync_policy(), SyncPolicy::EveryWrite);
        assert_eq!(config.max_frame_size().get(), DEFAULT_MAX_FRAME_SIZE);
        assert!(!config.create_if_missing());
        assert_eq!(
            config.journal_path(),
            Path::new("/tmp/ironfix/FIX.4.4-CLIENT_VENUE.journal")
        );
        assert_eq!(
            config.temp_path(),
            Path::new("/tmp/ironfix/FIX.4.4-CLIENT_VENUE.journal.tmp")
        );
        assert_eq!(
            config.lock_path(),
            Path::new("/tmp/ironfix/FIX.4.4-CLIENT_VENUE.lock")
        );
    }

    #[test]
    fn test_file_store_config_try_new_empty_name_is_rejected() {
        assert_eq!(
            FileStoreConfig::try_new("/tmp", ""),
            Err(FileStoreConfigError::EmptyName)
        );
    }

    #[test]
    fn test_file_store_config_try_new_long_name_is_rejected() {
        let name = "a".repeat(MAX_STORE_NAME_LEN + 1);
        assert_eq!(
            FileStoreConfig::try_new("/tmp", name),
            Err(FileStoreConfigError::NameTooLong {
                len: MAX_STORE_NAME_LEN + 1,
                max: MAX_STORE_NAME_LEN,
            })
        );
        // The limit itself is accepted.
        assert!(FileStoreConfig::try_new("/tmp", "a".repeat(MAX_STORE_NAME_LEN)).is_ok());
    }

    #[test]
    fn test_file_store_config_try_new_path_separator_is_rejected() {
        assert_eq!(
            FileStoreConfig::try_new("/tmp", "../escape"),
            Err(FileStoreConfigError::IllegalCharacter { character: '/' })
        );
        assert_eq!(
            FileStoreConfig::try_new("/tmp", "a\\b"),
            Err(FileStoreConfigError::IllegalCharacter { character: '\\' })
        );
        assert_eq!(
            FileStoreConfig::try_new("/tmp", "with space"),
            Err(FileStoreConfigError::IllegalCharacter { character: ' ' })
        );
        assert_eq!(
            FileStoreConfig::try_new("/tmp", "caf\u{e9}"),
            Err(FileStoreConfigError::IllegalCharacter {
                character: '\u{e9}'
            })
        );
    }

    #[test]
    fn test_file_store_config_try_new_leading_dot_is_rejected() {
        assert_eq!(
            FileStoreConfig::try_new("/tmp", ".."),
            Err(FileStoreConfigError::LeadingDot)
        );
        assert_eq!(
            FileStoreConfig::try_new("/tmp", ".hidden"),
            Err(FileStoreConfigError::LeadingDot)
        );
    }

    #[test]
    fn test_file_store_config_with_max_frame_size_above_limit_is_rejected() {
        let Ok(config) = FileStoreConfig::try_new("/tmp", "session") else {
            panic!("valid name");
        };
        let Some(above) = MAX_FRAME_SIZE_LIMIT
            .checked_add(1)
            .and_then(NonZeroU32::new)
        else {
            panic!("the limit is below u32::MAX");
        };
        assert_eq!(
            config.clone().with_max_frame_size(above),
            Err(FileStoreConfigError::MaxFrameSizeTooLarge {
                size: MAX_FRAME_SIZE_LIMIT + 1,
                max: MAX_FRAME_SIZE_LIMIT,
            })
        );

        let Some(limit) = NonZeroU32::new(MAX_FRAME_SIZE_LIMIT) else {
            panic!("the limit is non-zero");
        };
        let Ok(config) = config.with_max_frame_size(limit) else {
            panic!("the limit itself is accepted");
        };
        assert_eq!(config.max_frame_size(), limit);
    }

    #[test]
    fn test_file_store_config_with_create_if_missing_sets_it() {
        let Ok(config) = FileStoreConfig::try_new("/tmp", "session") else {
            panic!("valid name");
        };
        assert!(config.with_create_if_missing(true).create_if_missing());
    }

    #[test]
    fn test_file_store_config_try_new_windows_device_name_is_rejected() {
        for name in ["CON", "nul", "Com1", "LPT9", "aux.session", "prn.x.y"] {
            assert_eq!(
                FileStoreConfig::try_new("/tmp", name),
                Err(FileStoreConfigError::ReservedName {
                    name: name.to_string()
                }),
                "{name}"
            );
        }
        // Only the whole first part is reserved.
        for name in ["CONSOLE", "com10", "session.NUL", "LPT"] {
            assert!(FileStoreConfig::try_new("/tmp", name).is_ok(), "{name}");
        }
    }

    #[test]
    fn test_sync_policy_defaults_to_every_write() {
        assert_eq!(SyncPolicy::default(), SyncPolicy::EveryWrite);
        assert!(SyncPolicy::EveryWrite.flushes());
        assert!(SyncPolicy::EveryN(NonZeroU32::MIN).flushes());
        assert!(!SyncPolicy::Never.flushes());
    }

    #[test]
    fn test_sync_policy_damage_rule_follows_the_unflushed_window() {
        assert_eq!(
            SyncPolicy::EveryWrite.damage_rule(),
            DamageRule::Tail { records: 1 }
        );
        let Some(eight) = NonZeroU32::new(8) else {
            panic!("non-zero");
        };
        assert_eq!(
            SyncPolicy::EveryN(eight).damage_rule(),
            DamageRule::Tail { records: 8 }
        );
        assert_eq!(SyncPolicy::Never.damage_rule(), DamageRule::Anywhere);
    }
}
