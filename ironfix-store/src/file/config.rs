/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Configuration of a [`FileStore`](super::FileStore): where its files live,
//! what they are called, how large a frame may be, and when the journal is
//! flushed to stable storage.

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
/// flush (`fsync`, through [`std::fs::File::sync_data`]) protects against.
/// See `doc/adr/0006-file-store.md` for what each policy guarantees against
/// the crash points of issue #89.
///
/// A reset ([`MessageStore::reset`](crate::MessageStore::reset),
/// [`MessageStore::reset_to`](crate::MessageStore::reset_to)) and the creation
/// of a new journal write a complete new journal and rename it into place.
/// Under [`SyncPolicy::EveryWrite`] and [`SyncPolicy::EveryN`] the new file is
/// flushed before the rename and its directory after it; under
/// [`SyncPolicy::Never`] neither is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SyncPolicy {
    /// Flush after every journal write, before the call returns `Ok`.
    ///
    /// The only policy under which a write that returned `Ok` survives an
    /// operating-system crash or a power loss, and so the only one that turns
    /// the engine's write order into a guarantee against them. The default.
    #[default]
    EveryWrite,
    /// Flush after every `n`-th journal write.
    ///
    /// On an operating-system crash or a power loss, up to `n - 1` writes that
    /// returned `Ok` can be lost, together with the write in flight. A lost
    /// write can be a frame the counterparty already received and the sender
    /// counter that numbered it, so the next session can reuse a `MsgSeqNum`
    /// (34) with different content. `EveryN(1)` behaves as
    /// [`SyncPolicy::EveryWrite`].
    EveryN(NonZeroU32),
    /// Never flush, except through an explicit
    /// [`FileStore::sync`](super::FileStore::sync).
    ///
    /// Survives a process crash only. On an operating-system crash or a power
    /// loss any number of writes that returned `Ok` can be lost, and a journal
    /// replaced by a reset can come back empty, in which case
    /// [`FileStore::open`](super::FileStore::open) refuses it as corrupted.
    Never,
}

impl SyncPolicy {
    /// Whether a reset and a journal creation flush the new file and its
    /// directory.
    #[must_use]
    pub(crate) const fn flushes_replacements(self) -> bool {
        !matches!(self, Self::Never)
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
/// `BeginString` and CompIDs) when several share a directory.
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
///     .with_sync_policy(SyncPolicy::EveryN(NonZeroU32::new(16).ok_or("zero")?))
///     .with_max_frame_size(NonZeroU32::new(256 * 1024).ok_or("zero")?)?;
/// assert_eq!(config.name(), "FIX.4.4-CLIENT-VENUE");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStoreConfig {
    /// Directory holding the store's files; created at open if missing.
    directory: PathBuf,
    /// File-name-safe store name.
    name: String,
    /// When the journal is flushed.
    sync_policy: SyncPolicy,
    /// Largest frame accepted, in bytes.
    max_frame_size: NonZeroU32,
}

impl FileStoreConfig {
    /// Creates a configuration for the store `name` in `directory`, with
    /// [`SyncPolicy::EveryWrite`] and [`DEFAULT_MAX_FRAME_SIZE`].
    ///
    /// # Arguments
    /// * `directory` - Directory for the store's files; created at open if it
    ///   does not exist
    /// * `name` - The store's name, used in its file names: 1 to
    ///   [`MAX_STORE_NAME_LEN`] bytes of ASCII letters, digits, `.`, `-` and
    ///   `_`, not starting with `.`
    ///
    /// # Errors
    /// [`FileStoreConfigError::EmptyName`],
    /// [`FileStoreConfigError::NameTooLong`],
    /// [`FileStoreConfigError::IllegalCharacter`] or
    /// [`FileStoreConfigError::LeadingDot`] for a name that cannot be used as
    /// part of a file name.
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
        })
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
    fn test_sync_policy_defaults_to_every_write() {
        assert_eq!(SyncPolicy::default(), SyncPolicy::EveryWrite);
        assert!(SyncPolicy::EveryWrite.flushes_replacements());
        assert!(SyncPolicy::EveryN(NonZeroU32::MIN).flushes_replacements());
        assert!(!SyncPolicy::Never.flushes_replacements());
    }
}
