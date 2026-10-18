/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The on-disk format of a [`FileStore`](super::FileStore) journal: format
//! version 2 (ADR-0022), the only one this build reads and writes.
//!
//! All integers are little-endian.
//!
//! # Layout
//!
//! | Offset | Size | Content |
//! |---|---|---|
//! | 0 | 44 | header |
//! | 44 | 4 052 | zero bytes |
//! | 4 096 | 28 | counter slot 0 |
//! | 4 124 | 4 068 | zero bytes |
//! | 8 192 | 28 | counter slot 1 |
//! | 8 220 | 4 068 | zero bytes |
//! | 12 288 | | records, back to back, to the end of the file |
//!
//! The header and each counter slot sit alone in their own 4 KiB block, so
//! that a slot write torn by a power loss cannot reach the other slot or the
//! header on a device that writes in blocks of at most 4 KiB.
//!
//! # Header (44 bytes)
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 8 | magic, `IRFXJRNL` |
//! | 8 | 2 | format version, `2` |
//! | 10 | 2 | reserved, `0` |
//! | 12 | 8 | creation time, whole seconds since the Unix epoch |
//! | 20 | 4 | creation time, nanoseconds within the second |
//! | 24 | 8 | next sender `MsgSeqNum` the journal was written with |
//! | 32 | 8 | next target `MsgSeqNum` the journal was written with |
//! | 40 | 4 | CRC-32 of bytes 0..40 |
//!
//! The header's counters are the ones the journal was written with (created,
//! reset or compacted); the counter slots supersede them.
//!
//! # Counter slot (28 bytes)
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 8 | generation |
//! | 8 | 8 | next sender `MsgSeqNum` |
//! | 16 | 8 | next target `MsgSeqNum` |
//! | 24 | 4 | CRC-32 of bytes 0..24 |
//!
//! # Records
//!
//! Each record is a 12-byte record header and a body:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 4 | `len`, the body length in bytes |
//! | 4 | 4 | `!len`, the bitwise complement of `len` |
//! | 8 | 4 | CRC-32 of the body |
//! | 12 | `len` | body: a kind byte, then the kind's payload |
//!
//! The complement lets a loader tell a damaged record header (zeroed or
//! garbage bytes left by a crash) from a well-formed one, before it trusts
//! `len` to read anything.
//!
//! | Kind | Payload |
//! |---|---|
//! | 1, frame | `seq` u64, `msg_type` length u8, `msg_type` bytes, frame bytes |
//! | 5, frame and next sender | `seq` u64, `generation` u64, `next_sender` u64, `msg_type` length u8, `msg_type` bytes, frame bytes |
//!
//! Loading replays the records in file order: a later frame record for a
//! sequence number replaces an earlier one.
//!
//! # Generations
//!
//! Every write that changes a counter takes the next number of one
//! generation sequence the journal shares between its slots and its kind-5
//! records. A counter write overwrites the slot that does **not** hold the
//! newest valid slot, so the newest one is never written over: a write torn
//! by a crash damages only the older slot, and loading falls back to the
//! newer one, which is the state before the torn write. Loading takes the
//! next target from the newest valid slot, and the next sender from whichever
//! is newer, that slot or the kind-5 record with the highest generation. Both
//! slots failing their check is damage no single torn write can leave, and
//! refuses the journal.
//!
//! # Other versions
//!
//! Version 1, the format of #78 (counters as appended records), existed only
//! in development builds and was never released. It is refused with
//! [`StoreError::Corrupted`] naming the version, as is any version other than
//! 2.

use crate::file::crc32::crc32;
use crate::stored::StoredMessage;
use bytes::{Buf, Bytes};
use ironfix_core::error::StoreError;
use ironfix_core::message::{MSG_TYPE_MAX_LEN, MsgType};
use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::file::index::Index;

/// The first eight bytes of every journal.
const MAGIC: [u8; 8] = *b"IRFXJRNL";

/// The format version this module reads and writes.
pub(crate) const VERSION: u16 = 2;

/// Length of the journal header, in bytes.
pub(crate) const HEADER_LEN: usize = 44;

/// Length of the journal header as a file offset, in bytes.
pub(crate) const HEADER_LEN_U64: u64 = 44;

/// Length of a record header, in bytes.
pub(crate) const RECORD_HEADER_LEN: usize = 12;

/// Length of a record header as a file offset, in bytes.
pub(crate) const RECORD_HEADER_LEN_U64: u64 = 12;

/// Size of the blocks the header and each counter slot sit alone in, in
/// bytes.
const BLOCK_LEN: usize = 4096;

/// File offsets of the two counter slots, in bytes.
pub(crate) const SLOT_OFFSETS: [u64; 2] = [4096, 8192];

/// File offset of the first record, in bytes: the length of the prefix that
/// holds the header and the slots.
pub(crate) const DATA_START: u64 = 12_288;

/// [`DATA_START`] as a buffer length.
const PREFIX_LEN: usize = 3 * BLOCK_LEN;

/// Length of a counter slot, in bytes.
pub(crate) const SLOT_LEN: usize = 28;

/// Length of the part of a counter slot its CRC covers, in bytes.
const SLOT_CHECKED_LEN: usize = 24;

// The layout constants agree: the prefix is three blocks, the header fits the
// first one, and each slot starts its own block and fits in it.
const _: () = {
    assert!(PREFIX_LEN as u64 == DATA_START);
    assert!(HEADER_LEN <= BLOCK_LEN);
    assert!(SLOT_OFFSETS[0] == BLOCK_LEN as u64);
    assert!(SLOT_OFFSETS[1] == 2 * BLOCK_LEN as u64);
    assert!(SLOT_LEN <= BLOCK_LEN);
    assert!(SLOT_OFFSETS[1] + BLOCK_LEN as u64 == DATA_START);
    assert!(SLOT_CHECKED_LEN + 4 == SLOT_LEN);
};

/// Largest part of a record body that is not frame bytes: the kind, the
/// sequence number, the generation, the next sender number, the `MsgType`
/// length and the longest `MsgType`.
pub(crate) const MAX_BODY_OVERHEAD: u64 = 1 + 8 + 8 + 8 + 1 + MSG_TYPE_MAX_LEN as u64;

/// Kind byte of a frame record.
const KIND_FRAME: u8 = 1;

/// Kind byte of a frame, generation and next sender record.
const KIND_FRAME_AND_SENDER: u8 = 5;

/// Offset of the generation inside a kind-5 record, header included: the
/// record header, the kind and the sequence number come first.
const GENERATION_AT: usize = RECORD_HEADER_LEN + 1 + 8;

/// Billion, the number of nanoseconds in a second.
const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// Size of the buffer used to check that a tail is all zero bytes.
const ZERO_CHECK_CHUNK: usize = 4096;

/// Why a [`FileStore`](super::FileStore) cut its journal short when it opened,
/// refreshed or repaired it.
///
/// Recovery never returns a record it cannot vouch for. A record cut away is
/// removed from the file **together with everything after it**. Which damage
/// is cut and which refuses the journal is set out in the
/// [module documentation](super), "Recovery".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TruncationCause {
    /// The file ends inside a record: a write was interrupted, which is what a
    /// crash during an append leaves. Only the interrupted write is lost.
    Incomplete,
    /// A record's header or body failed its check, where an interrupted write
    /// can have left it (at the tail, within what the sync policy leaves
    /// unflushed, or followed only by zero bytes), or anywhere under
    /// [`SyncPolicy::Never`](super::SyncPolicy::Never) and
    /// [`FileStore::repair`](super::FileStore::repair). After a repair, the
    /// records dropped can include ones that were acknowledged.
    Damaged,
}

/// A cut the store made to its journal while opening, refreshing or repairing
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncation {
    /// File offset the journal was cut at, in bytes: the start of the first
    /// record that was dropped.
    offset: u64,
    /// Number of bytes dropped from the end of the file.
    dropped_bytes: u64,
    /// Why the record at `offset` was dropped.
    cause: TruncationCause,
}

impl Truncation {
    /// Returns the file offset the journal was cut at, in bytes.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the number of bytes dropped from the end of the file.
    #[must_use]
    pub const fn dropped_bytes(&self) -> u64 {
        self.dropped_bytes
    }

    /// Returns why the first dropped record was dropped.
    #[must_use]
    pub const fn cause(&self) -> TruncationCause {
        self.cause
    }
}

/// Which damage recovery may cut; anything else refuses the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DamageRule {
    /// Cut only damage an interrupted write can have left: a record whose
    /// body fails its CRC and is the last in the file, a damaged record header
    /// within one maximum-size record of the end, or either one followed only
    /// by zero bytes. With `records` above 1 (a policy that leaves up to that
    /// many writes unflushed) the window is `records` maximum-size records for
    /// both. Under [`SyncPolicy::EveryWrite`](super::SyncPolicy::EveryWrite)
    /// and [`SyncPolicy::EveryN`](super::SyncPolicy::EveryN).
    Tail {
        /// How many writes the policy can leave unflushed.
        records: u64,
    },
    /// Cut at the first record that fails its check, wherever it is. Under
    /// [`SyncPolicy::Never`](super::SyncPolicy::Never), which promises
    /// nothing after an operating-system crash.
    Anywhere,
    /// Cut at the first record that cannot be read for any reason, including
    /// a well-formed one this configuration refuses. Only for
    /// [`FileStore::repair`](super::FileStore::repair).
    Salvage,
}

/// The fixed part of a journal: when it was created and the counters it was
/// written with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    /// When the journal was created (by the first open or the last reset).
    pub(crate) creation_time: SystemTime,
    /// Next sender sequence number the journal was written with.
    pub(crate) next_sender: u64,
    /// Next target sequence number the journal was written with.
    pub(crate) next_target: u64,
}

/// Where one filed frame's record is in the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IndexEntry {
    /// File offset of the record header, in bytes.
    pub(crate) offset: u64,
    /// Length of the record body, in bytes.
    pub(crate) body_len: u32,
}

impl IndexEntry {
    /// Length of the whole record, header included, in bytes.
    #[must_use]
    pub(crate) fn record_len(self) -> u64 {
        RECORD_HEADER_LEN_U64 + u64::from(self.body_len)
    }
}

/// The two counter slots, as their bytes on disk.
pub(crate) type SlotImages = [[u8; SLOT_LEN]; 2];

/// The content of one counter slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Slot {
    /// Where the slot stands in the journal's generation sequence.
    pub(crate) generation: u64,
    /// Next sender sequence number.
    pub(crate) next_sender: u64,
    /// Next target sequence number.
    pub(crate) next_target: u64,
}

/// What a journal holds, as recovered by [`scan`].
#[derive(Debug)]
pub(crate) struct Scan {
    /// The journal header.
    pub(crate) header: Header,
    /// Both counter slots, as on disk.
    pub(crate) slots: SlotImages,
    /// The position of the newest valid slot.
    pub(crate) active: usize,
    /// Every filed frame's record, by sequence number.
    pub(crate) index: Index,
    /// The next sender sequence number.
    pub(crate) next_sender: u64,
    /// The next target sequence number.
    pub(crate) next_target: u64,
    /// The generation the next counter write takes: above every one in the
    /// journal.
    pub(crate) next_generation: u64,
    /// File offset just past the last good record.
    pub(crate) end: u64,
    /// The cut recovery has to make, if any. The scan does not make it.
    pub(crate) truncation: Option<Truncation>,
    /// Bytes taken by records a later record for the same number replaced.
    pub(crate) dead_bytes: u64,
}

/// One decoded record body.
#[derive(Debug, PartialEq, Eq)]
struct Body<'a> {
    /// The `MsgSeqNum` (34) the frame was filed under.
    seq: u64,
    /// The generation and the next sender number filed with it, for kind 5.
    counter: Option<(u64, u64)>,
    /// The `MsgType` (35) it was filed as.
    msg_type: MsgType,
    /// The frame bytes: the tail of the record.
    frame: &'a [u8],
}

/// Positional reads of a journal: one call reads one whole record.
pub(crate) trait ReadAt {
    /// Fills `buf` from the bytes at `offset`.
    ///
    /// # Errors
    /// The I/O error, including an unexpected end of file.
    fn read_record_at(&mut self, buf: &mut [u8], offset: u64) -> std::io::Result<()>;
}

impl ReadAt for std::fs::File {
    #[cfg(unix)]
    fn read_record_at(&mut self, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, buf, offset)
    }

    #[cfg(not(unix))]
    fn read_record_at(&mut self, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom};
        self.seek(SeekFrom::Start(offset))?;
        self.read_exact(buf)
    }
}

#[cfg(test)]
impl<T: AsRef<[u8]>> ReadAt for std::io::Cursor<T> {
    fn read_record_at(&mut self, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom};
        self.seek(SeekFrom::Start(offset))?;
        self.read_exact(buf)
    }
}

/// Builds a [`StoreError::Corrupted`] for a reason.
#[cold]
#[inline(never)]
pub(crate) fn corrupted(reason: String) -> StoreError {
    StoreError::Corrupted { reason }
}

/// Builds the [`StoreError::Corrupted`] for damage recovery may not cut.
#[cold]
#[inline(never)]
fn refused(offset: u64, what: &str, remaining: u64) -> StoreError {
    corrupted(format!(
        "record at offset {offset} {what}, and the {remaining} bytes from there to the end of \
         the journal are more than an interrupted write can leave: this is damage to data \
         already written, so the store refuses to open. FileStore::repair cuts the journal \
         there; the session must then reset its sequence (ResetSeqNumFlag 141=Y)"
    ))
}

/// Builds a [`StoreError::Io`] for an I/O error, with what was being done.
#[cold]
#[inline(never)]
pub(crate) fn io_error(context: &str, err: &std::io::Error) -> StoreError {
    StoreError::Io(format!("{context}: {err}"))
}

/// Builds the [`StoreError::Corrupted`] for a record that no longer matches
/// what the index says of it.
#[cold]
#[inline(never)]
fn record_mismatch(seq: u64, offset: u64, what: &str) -> StoreError {
    corrupted(format!(
        "record for MsgSeqNum {seq} at offset {offset} {what}"
    ))
}

/// Encodes a journal header.
#[must_use]
pub(crate) fn encode_header(header: &Header) -> [u8; HEADER_LEN] {
    encode_versioned_header(header, VERSION)
}

/// Encodes a journal header declaring format `version`.
#[must_use]
fn encode_versioned_header(header: &Header, version: u16) -> [u8; HEADER_LEN] {
    // A clock before the Unix epoch is recorded as the epoch: the creation
    // time is informational, and refusing to create or reset a store over it
    // would be worse than recording it imprecisely.
    let since_epoch = header
        .creation_time
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let mut bytes = [0u8; HEADER_LEN];
    let mut out = Writer::new(&mut bytes);
    out.put(&MAGIC);
    out.put(&version.to_le_bytes());
    out.put(&0u16.to_le_bytes());
    out.put(&since_epoch.as_secs().to_le_bytes());
    out.put(&since_epoch.subsec_nanos().to_le_bytes());
    out.put(&header.next_sender.to_le_bytes());
    out.put(&header.next_target.to_le_bytes());
    let crc = crc32(out.written());
    out.put(&crc.to_le_bytes());
    bytes
}

/// Decodes a journal header.
///
/// # Errors
/// [`StoreError::Corrupted`] if the bytes are not a journal header, or
/// declare a format version other than [`VERSION`]; the error names the
/// version.
pub(crate) fn decode_header(bytes: &[u8; HEADER_LEN]) -> Result<Header, StoreError> {
    let (checked, crc) = bytes.split_at(HEADER_LEN - 4);
    let mut crc_reader = Reader::new(crc);
    if crc32(checked) != crc_reader.u32()? {
        return Err(corrupted(
            "journal header fails its checksum: not a journal, or a damaged one".to_string(),
        ));
    }
    let mut input = Reader::new(checked);
    if input.take(MAGIC.len())? != MAGIC {
        return Err(corrupted(
            "file does not start with the journal magic: not an IronFix journal".to_string(),
        ));
    }
    let version = input.u16()?;
    if version != VERSION {
        return Err(corrupted(format!(
            "journal format version {version} is not supported; this build reads version \
             {VERSION} only (version 1 was a development format that was never released)"
        )));
    }
    let _reserved = input.u16()?;
    let secs = input.u64()?;
    let nanos = input.u32()?;
    if nanos >= NANOS_PER_SECOND {
        return Err(corrupted(format!(
            "journal creation time has {nanos} nanoseconds in a second"
        )));
    }
    let creation_time = UNIX_EPOCH
        .checked_add(Duration::new(secs, nanos))
        .ok_or_else(|| corrupted(format!("journal creation time {secs}s is out of range")))?;
    Ok(Header {
        creation_time,
        next_sender: input.u64()?,
        next_target: input.u64()?,
    })
}

/// Encodes a counter slot.
#[must_use]
pub(crate) fn encode_slot(slot: &Slot) -> [u8; SLOT_LEN] {
    let mut bytes = [0u8; SLOT_LEN];
    let mut out = Writer::new(&mut bytes);
    out.put(&slot.generation.to_le_bytes());
    out.put(&slot.next_sender.to_le_bytes());
    out.put(&slot.next_target.to_le_bytes());
    let crc = crc32(out.written());
    out.put(&crc.to_le_bytes());
    bytes
}

/// Decodes a counter slot, or `None` if it fails its CRC (a torn or damaged
/// slot).
#[must_use]
pub(crate) fn decode_slot(bytes: &[u8; SLOT_LEN]) -> Option<Slot> {
    let (checked, crc) = bytes.split_at(SLOT_CHECKED_LEN);
    let crc = crc.first_chunk::<4>().map(|crc| u32::from_le_bytes(*crc))?;
    if crc32(checked) != crc {
        return None;
    }
    let mut input = Reader::new(checked);
    Some(Slot {
        generation: input.u64().ok()?,
        next_sender: input.u64().ok()?,
        next_target: input.u64().ok()?,
    })
}

/// The slot a journal's counters come from: the newest valid one. Returns
/// its position (0 or 1) and its content.
///
/// # Errors
/// [`StoreError::Corrupted`] if neither slot is valid, or both carry the same
/// generation with different counters: no single torn write leaves either.
pub(crate) fn newest_slot(images: &SlotImages) -> Result<(usize, Slot), StoreError> {
    let [first, second] = images.each_ref().map(decode_slot);
    match (first, second) {
        (Some(first), Some(second)) => {
            if second.generation > first.generation {
                Ok((1, second))
            } else if first.generation > second.generation || first == second {
                Ok((0, first))
            } else {
                Err(corrupted(format!(
                    "both counter slots carry generation {} with different counters: the \
                     journal is damaged",
                    first.generation
                )))
            }
        }
        (Some(first), None) => Ok((0, first)),
        (None, Some(second)) => Ok((1, second)),
        (None, None) => Err(corrupted(
            "both counter slots fail their checksum: no interrupted write damages both, so the \
             journal is damaged and its counters are unknown"
                .to_string(),
        )),
    }
}

/// Two slots for a journal that starts from the given counters: generations
/// `first` and `first + 1`. Returns them with the next generation to use.
///
/// # Errors
/// [`StoreError::Io`] if the generation sequence is exhausted.
pub(crate) fn fresh_slots(
    first: u64,
    next_sender: u64,
    next_target: u64,
) -> Result<(SlotImages, u64), StoreError> {
    let exhausted = || {
        StoreError::Io(
            "the journal's generation sequence is exhausted; reset the store".to_string(),
        )
    };
    let second = first.checked_add(1).ok_or_else(exhausted)?;
    let next = second.checked_add(1).ok_or_else(exhausted)?;
    let slot = |generation| {
        encode_slot(&Slot {
            generation,
            next_sender,
            next_target,
        })
    };
    Ok(([slot(first), slot(second)], next))
}

/// Encodes the prefix of a journal: the header and both slots, in their
/// blocks, [`DATA_START`] bytes.
#[must_use]
pub(crate) fn encode_prefix(header: &Header, slots: &SlotImages) -> Vec<u8> {
    let mut prefix = vec![0u8; PREFIX_LEN];
    if let Some(at) = prefix.get_mut(..HEADER_LEN) {
        at.copy_from_slice(&encode_header(header));
    }
    for (image, offset) in slots.iter().zip(SLOT_OFFSETS) {
        let at = usize::try_from(offset)
            .ok()
            .and_then(|start| prefix.get_mut(start..start.checked_add(SLOT_LEN)?));
        if let Some(at) = at {
            at.copy_from_slice(image);
        }
    }
    prefix
}

/// Encodes a frame record into `record`, kind 1 without a next sender number
/// and kind 5 with one, reusing its capacity: `record` is cleared, and grows
/// only if it holds less than the record. The record is **not sealed**: the
/// generation of a kind-5 record is taken when the record is written, so the
/// writer seals it with [`seal_frame_record`].
///
/// `max_frame_size` is the configured limit, in bytes.
///
/// # Errors
/// [`StoreError::StoreFailed`] if the frame is above `max_frame_size`. The
/// error never contains frame bytes. `record` is then left cleared.
pub(crate) fn encode_frame_record_into(
    record: &mut Vec<u8>,
    seq: u64,
    next_sender: Option<u64>,
    msg_type: &MsgType,
    frame: &[u8],
    max_frame_size: u32,
) -> Result<(), StoreError> {
    record.clear();
    let frame_len = u32::try_from(frame.len())
        .ok()
        .filter(|len| *len <= max_frame_size)
        .ok_or_else(|| StoreError::StoreFailed {
            seq_num: seq,
            reason: format!(
                "frame of {} bytes is above the store's {max_frame_size}-byte limit",
                frame.len()
            ),
        })?;
    let code = msg_type.as_str().as_bytes();
    // A `MsgType` is at most MSG_TYPE_MAX_LEN (8) bytes, so its length fits a
    // byte and the body length fits a u32 below MAX_FRAME_SIZE_LIMIT plus the
    // overhead.
    let code_len = u8::try_from(code.len()).map_err(|_| StoreError::StoreFailed {
        seq_num: seq,
        reason: format!("msg type of {} bytes cannot be filed", code.len()),
    })?;
    let overflow = || StoreError::StoreFailed {
        seq_num: seq,
        reason: "record length overflows".to_string(),
    };
    // The kind, the sequence number, the generation and next sender of kind
    // 5, and the code length.
    let fixed: u32 = if next_sender.is_some() {
        1 + 8 + 16 + 1
    } else {
        1 + 8 + 1
    };
    let body_len = fixed
        .checked_add(u32::from(code_len))
        .and_then(|len| len.checked_add(frame_len))
        .ok_or_else(overflow)?;
    let record_len = usize::try_from(body_len)
        .ok()
        .and_then(|len| len.checked_add(RECORD_HEADER_LEN))
        .ok_or_else(overflow)?;

    record.reserve_exact(record_len);
    record.extend_from_slice(&body_len.to_le_bytes());
    record.extend_from_slice(&[0u8; RECORD_HEADER_LEN - 4]);
    match next_sender {
        Some(next_sender) => {
            record.push(KIND_FRAME_AND_SENDER);
            record.extend_from_slice(&seq.to_le_bytes());
            // The generation, written when the record is sealed.
            record.extend_from_slice(&0u64.to_le_bytes());
            record.extend_from_slice(&next_sender.to_le_bytes());
        }
        None => {
            record.push(KIND_FRAME);
            record.extend_from_slice(&seq.to_le_bytes());
        }
    }
    record.push(code_len);
    record.extend_from_slice(code);
    record.extend_from_slice(frame);
    Ok(())
}

/// Encodes a frame record into a new buffer of exactly its length (see
/// [`encode_frame_record_into`]).
///
/// # Errors
/// As [`encode_frame_record_into`].
#[cfg(test)]
pub(crate) fn encode_frame_record(
    seq: u64,
    next_sender: Option<u64>,
    msg_type: &MsgType,
    frame: &[u8],
    max_frame_size: u32,
) -> Result<Vec<u8>, StoreError> {
    let mut record = Vec::new();
    encode_frame_record_into(
        &mut record,
        seq,
        next_sender,
        msg_type,
        frame,
        max_frame_size,
    )?;
    Ok(record)
}

/// Seals a record from [`encode_frame_record_into`]: writes `generation`
/// into a kind-5 record (it is ignored for kind 1) and fills in the record
/// header.
pub(crate) fn seal_frame_record(record: &mut [u8], generation: u64) {
    if takes_generation(record) {
        let at = GENERATION_AT
            .checked_add(8)
            .and_then(|end| record.get_mut(GENERATION_AT..end));
        if let Some(at) = at {
            at.copy_from_slice(&generation.to_le_bytes());
        }
    }
    let body_len = record_body_len(record);
    seal(record, body_len);
}

/// Whether an encoded record carries a counter, and so takes a generation.
#[must_use]
pub(crate) fn takes_generation(record: &[u8]) -> bool {
    record.get(RECORD_HEADER_LEN).copied() == Some(KIND_FRAME_AND_SENDER)
}

/// Fills in the record header of `record`, whose body (of `body_len` bytes)
/// follows the 12 header bytes reserved for it.
fn seal(record: &mut [u8], body_len: u32) {
    if let Some((head, body)) = record.split_at_mut_checked(RECORD_HEADER_LEN) {
        let crc = crc32(body);
        let mut out = Writer::new(head);
        out.put(&body_len.to_le_bytes());
        out.put(&(!body_len).to_le_bytes());
        out.put(&crc.to_le_bytes());
    }
}

/// Returns the body length of an encoded record, as [`IndexEntry`] keeps it.
#[must_use]
pub(crate) fn record_body_len(record: &[u8]) -> u32 {
    record
        .first_chunk::<4>()
        .map_or(0, |len| u32::from_le_bytes(*len))
}

/// Decodes a record body whose CRC has been checked.
///
/// # Errors
/// The reason the body is not a record of this format, for the caller to
/// place.
fn decode_body(body: &[u8]) -> Result<Body<'_>, String> {
    let mut input = Reader::new(body);
    let kind = input.u8().map_err(|_| "empty record body".to_string())?;
    let short = |_| format!("record of kind {kind} is shorter than its fields");
    let counter_follows = match kind {
        KIND_FRAME => false,
        KIND_FRAME_AND_SENDER => true,
        other => return Err(format!("unknown record kind {other}")),
    };
    let seq = input.u64().map_err(short)?;
    let counter = if counter_follows {
        Some((input.u64().map_err(short)?, input.u64().map_err(short)?))
    } else {
        None
    };
    let code_len = usize::from(input.u8().map_err(short)?);
    let code = input.take(code_len).map_err(short)?;
    let msg_type = std::str::from_utf8(code)
        .ok()
        .and_then(|code| MsgType::new(code).ok())
        .ok_or_else(|| format!("record for MsgSeqNum {seq} carries an invalid MsgType"))?;
    Ok(Body {
        seq,
        counter,
        msg_type,
        frame: input.rest(),
    })
}

/// Reads the next `len` bytes from `reader` and reports whether every one is
/// zero. Reads in bounded chunks.
fn rest_is_zero<R: Read>(reader: &mut R, len: u64) -> Result<bool, StoreError> {
    let mut chunk = [0u8; ZERO_CHECK_CHUNK];
    let mut left = len;
    while left > 0 {
        let take =
            usize::try_from(left).map_or(ZERO_CHECK_CHUNK, |left| left.min(ZERO_CHECK_CHUNK));
        let Some(part) = chunk.get_mut(..take) else {
            return Ok(false);
        };
        reader
            .read_exact(part)
            .map_err(|err| io_error("cannot read the journal's tail", &err))?;
        if part.iter().any(|byte| *byte != 0) {
            return Ok(false);
        }
        // `take` is at most `left`.
        left -= take as u64;
    }
    Ok(true)
}

/// The largest record `max_body` allows, header included, in bytes.
const fn max_record(max_body: u64) -> u64 {
    RECORD_HEADER_LEN_U64 + max_body
}

/// Whether `remaining` bytes fit in `records` maximum-size records.
fn within_records(remaining: u64, records: u64, max_body: u64) -> bool {
    // An overflowing window is larger than any file.
    records
        .checked_mul(max_record(max_body))
        .is_none_or(|window| remaining <= window)
}

/// The records of a journal, replayed while it is scanned.
struct Replay {
    /// Every filed frame's record, by sequence number.
    index: Index,
    /// Bytes taken by replaced records.
    dead_bytes: u64,
    /// The generation and next sender of the newest kind-5 record.
    newest_counter: Option<(u64, u64)>,
    /// The highest generation seen in a record.
    highest_generation: Option<u64>,
}

impl Replay {
    /// Takes the body (`len` bytes) of the record at `offset`.
    ///
    /// # Errors
    /// The reason the body is not a record of this format.
    fn record(&mut self, offset: u64, len: u32, body: &[u8]) -> Result<(), String> {
        let body = decode_body(body)?;
        if let Some((generation, next_sender)) = body.counter {
            if self
                .newest_counter
                .is_none_or(|(newest, _)| generation > newest)
            {
                self.newest_counter = Some((generation, next_sender));
            }
            self.highest_generation = Some(
                self.highest_generation
                    .map_or(generation, |highest| highest.max(generation)),
            );
        }
        let entry = IndexEntry {
            offset,
            body_len: len,
        };
        if let Some(replaced) = self.index.insert(body.seq, entry) {
            self.dead_bytes = self
                .dead_bytes
                .checked_add(replaced.record_len())
                .ok_or_else(|| "the count of replaced bytes overflows".to_string())?;
        }
        Ok(())
    }
}

/// Reads a journal from its start, `file_len` bytes long, and recovers what
/// it holds.
///
/// `max_body` is the largest record body the configuration allows, in bytes;
/// no more than that is ever allocated for one record. `rule` decides which
/// damage among the records is cut (reported in [`Scan::truncation`]) and
/// which refuses the journal. The scan does not modify the file.
///
/// # Errors
/// [`StoreError::Corrupted`] if the file is shorter than [`DATA_START`], its
/// header is not a journal header of this format version, both counter slots
/// are unreadable (whatever `rule`), damage `rule` does not allow to be cut
/// is found, or, unless `rule` is [`DamageRule::Salvage`], a record with a
/// well-formed header declares a body of 0 bytes or above `max_body`, or a
/// record that passes its CRC does not decode. [`StoreError::Io`] if reading
/// fails.
pub(crate) fn scan<R: Read>(
    mut reader: R,
    file_len: u64,
    max_body: u64,
    rule: DamageRule,
) -> Result<Scan, StoreError> {
    if file_len < HEADER_LEN_U64 {
        return Err(corrupted(format!(
            "journal is {file_len} bytes long, shorter than its {HEADER_LEN}-byte header"
        )));
    }
    let mut header_bytes = [0u8; HEADER_LEN];
    reader
        .read_exact(&mut header_bytes)
        .map_err(|err| io_error("cannot read the journal header", &err))?;
    let header = decode_header(&header_bytes)?;
    if file_len < DATA_START {
        return Err(corrupted(format!(
            "journal is {file_len} bytes long, shorter than the {DATA_START} bytes its header \
             and counter slots take"
        )));
    }
    let mut prefix = vec![0u8; PREFIX_LEN - HEADER_LEN];
    reader
        .read_exact(&mut prefix)
        .map_err(|err| io_error("cannot read the journal's counter slots", &err))?;
    let mut slots: SlotImages = [[0u8; SLOT_LEN]; 2];
    for (image, offset) in slots.iter_mut().zip(SLOT_OFFSETS) {
        let bytes = usize::try_from(offset)
            .ok()
            .and_then(|start| start.checked_sub(HEADER_LEN))
            .and_then(|start| prefix.get(start..start.checked_add(SLOT_LEN)?))
            .ok_or_else(|| corrupted("counter slot is outside the journal".to_string()))?;
        image.copy_from_slice(bytes);
    }
    let (active, slot) = newest_slot(&slots)?;

    let mut replay = Replay {
        index: Index::new(),
        dead_bytes: 0,
        newest_counter: None,
        highest_generation: None,
    };
    let (end, truncation) = scan_records(
        &mut reader,
        DATA_START,
        file_len,
        max_body,
        rule,
        |offset, len, body| replay.record(offset, len, body),
    )?;

    let next_sender = match replay.newest_counter {
        Some((generation, next_sender)) if generation > slot.generation => next_sender,
        _ => slot.next_sender,
    };
    let highest = slots
        .iter()
        .filter_map(decode_slot)
        .map(|slot| slot.generation)
        .chain(replay.highest_generation)
        .max()
        .unwrap_or(slot.generation);
    let next_generation = highest
        .checked_add(1)
        .ok_or_else(|| corrupted("the journal's generation sequence is exhausted".to_string()))?;
    Ok(Scan {
        header,
        slots,
        active,
        index: replay.index,
        next_sender,
        next_target: slot.next_target,
        next_generation,
        end,
        truncation,
        dead_bytes: replay.dead_bytes,
    })
}

/// Reads the records of a journal from `start` (where `reader` is
/// positioned) to `file_len`, hands each whole record whose CRC passes to
/// `record`, and stops at the first one it cannot read. Returns the offset
/// past the last good record and the cut recovery has to make, if any.
///
/// # Errors
/// As [`scan`], for the records.
fn scan_records<R: Read>(
    reader: &mut R,
    start: u64,
    file_len: u64,
    max_body: u64,
    rule: DamageRule,
    mut record: impl FnMut(u64, u32, &[u8]) -> Result<(), String>,
) -> Result<(u64, Option<Truncation>), StoreError> {
    let mut end = start;
    let mut truncation = None;
    let mut body = Vec::new();
    loop {
        let offset = end;
        // `end` only ever advances past records that fit in the file.
        let remaining = file_len
            .checked_sub(offset)
            .ok_or_else(|| corrupted(format!("journal offset {offset} is past its end")))?;
        if remaining == 0 {
            break;
        }
        let cut = |cause| Truncation {
            offset,
            dropped_bytes: remaining,
            cause,
        };
        // A partial record header is always an interrupted write at the tail.
        if remaining < RECORD_HEADER_LEN_U64 {
            truncation = Some(cut(TruncationCause::Incomplete));
            break;
        }
        let mut record_header = [0u8; RECORD_HEADER_LEN];
        reader
            .read_exact(&mut record_header)
            .map_err(|err| io_error("cannot read a journal record header", &err))?;
        let mut fields = Reader::new(&record_header);
        let len = fields.u32()?;
        let check = fields.u32()?;
        let crc = fields.u32()?;

        if check != !len {
            let may_cut = match rule {
                DamageRule::Anywhere | DamageRule::Salvage => true,
                DamageRule::Tail { records } => {
                    within_records(remaining, records, max_body)
                        || (record_header == [0u8; RECORD_HEADER_LEN]
                            && rest_is_zero(reader, remaining - RECORD_HEADER_LEN_U64)?)
                }
            };
            if !may_cut {
                return Err(refused(offset, "has a damaged record header", remaining));
            }
            truncation = Some(cut(TruncationCause::Damaged));
            break;
        }
        if len == 0 || u64::from(len) > max_body {
            if rule == DamageRule::Salvage {
                truncation = Some(cut(TruncationCause::Damaged));
                break;
            }
            return Err(corrupted(format!(
                "record at offset {offset} declares a {len}-byte body; this store reads bodies \
                 of 1 to {max_body} bytes (was the journal written with a larger max frame size?)"
            )));
        }
        let record_len = RECORD_HEADER_LEN_U64 + u64::from(len);
        // The file ends inside a well-formed record: an interrupted write.
        if remaining < record_len {
            truncation = Some(cut(TruncationCause::Incomplete));
            break;
        }
        // Bounded by `max_body`, checked above.
        let body_len = usize::try_from(len)
            .map_err(|_| corrupted(format!("record at offset {offset} is too long")))?;
        body.resize(body_len, 0);
        reader
            .read_exact(&mut body)
            .map_err(|err| io_error("cannot read a journal record", &err))?;
        if crc32(&body) != crc {
            let after = remaining - record_len;
            let may_cut = match rule {
                DamageRule::Anywhere | DamageRule::Salvage => true,
                DamageRule::Tail { records } => {
                    after == 0
                        || (records > 1 && within_records(remaining, records, max_body))
                        || rest_is_zero(reader, after)?
                }
            };
            if !may_cut {
                return Err(refused(offset, "fails its checksum", remaining));
            }
            truncation = Some(cut(TruncationCause::Damaged));
            break;
        }
        match record(offset, len, &body) {
            Ok(()) => {}
            Err(_) if rule == DamageRule::Salvage => {
                truncation = Some(cut(TruncationCause::Damaged));
                break;
            }
            Err(reason) => {
                return Err(corrupted(format!("record at offset {offset}: {reason}")));
            }
        }
        end = offset
            .checked_add(record_len)
            .ok_or_else(|| corrupted("journal offset overflows".to_string()))?;
    }
    Ok((end, truncation))
}

/// Reads the whole record `entry` points at (the one filed under `seq`) into
/// `record`, reusing its capacity, in one positional read, and checks it
/// again: its length, its complement, its CRC, and that it decodes as the
/// frame filed under `seq`. Returns the offset of the frame in the record and
/// its `MsgType`.
///
/// # Errors
/// [`StoreError::Corrupted`] if the record no longer matches the index, fails
/// its CRC or is not `seq`'s frame (the disk changed under the store);
/// [`StoreError::Io`] if reading fails.
pub(crate) fn read_record_into<F: ReadAt>(
    file: &mut F,
    seq: u64,
    entry: IndexEntry,
    record: &mut Vec<u8>,
) -> Result<(usize, MsgType), StoreError> {
    let IndexEntry { offset, body_len } = entry;
    // `body_len` was bounded by the configured limit when it was indexed.
    let record_len = usize::try_from(body_len)
        .ok()
        .and_then(|len| len.checked_add(RECORD_HEADER_LEN))
        .ok_or_else(|| record_mismatch(seq, offset, "is too long to read"))?;
    record.clear();
    record.resize(record_len, 0);
    file.read_record_at(record, offset).map_err(|err| {
        // The record was indexed whole, so a file that now ends inside it
        // was cut under the store: that is damage, not a failed read.
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            record_mismatch(
                seq,
                offset,
                "is no longer whole in the journal: it was cut after it was indexed",
            )
        } else {
            io_error("cannot read a journal record", &err)
        }
    })?;
    let (head, body) = record
        .split_at_checked(RECORD_HEADER_LEN)
        .ok_or_else(|| record_mismatch(seq, offset, "is shorter than its header"))?;
    let mut fields = Reader::new(head);
    let len = fields.u32()?;
    let check = fields.u32()?;
    let crc = fields.u32()?;
    if len != body_len || check != !len {
        return Err(record_mismatch(seq, offset, "no longer matches the index"));
    }
    if crc32(body) != crc {
        return Err(record_mismatch(seq, offset, "fails its checksum"));
    }
    match decode_body(body) {
        Ok(Body {
            seq: filed,
            msg_type,
            frame,
            ..
        }) if filed == seq => {
            // The frame is the tail of the record.
            let at = record_len
                .checked_sub(frame.len())
                .ok_or_else(|| record_mismatch(seq, offset, "has a frame longer than itself"))?;
            Ok((at, msg_type))
        }
        Ok(_) => Err(record_mismatch(seq, offset, "is not that message's frame")),
        Err(reason) => Err(record_mismatch(seq, offset, &reason)),
    }
}

/// Reads the frame filed under `seq` from the record `entry` points at, in
/// one positional read, checking the record again on the way.
///
/// # Errors
/// As [`read_record_into`].
pub(crate) fn read_frame<F: ReadAt>(
    file: &mut F,
    seq: u64,
    entry: IndexEntry,
) -> Result<StoredMessage, StoreError> {
    let mut record = Vec::new();
    let (frame_at, msg_type) = read_record_into(file, seq, entry, &mut record)?;
    let mut payload = Bytes::from(record);
    payload.advance(frame_at);
    Ok(StoredMessage::new(seq, msg_type, payload))
}

/// Writes fields into a fixed buffer, front to back.
struct Writer<'b> {
    /// The buffer.
    buffer: &'b mut [u8],
    /// Bytes written so far.
    at: usize,
}

impl<'b> Writer<'b> {
    /// Starts writing at the front of `buffer`.
    const fn new(buffer: &'b mut [u8]) -> Self {
        Self { buffer, at: 0 }
    }

    /// Appends `bytes`. The callers size the buffer for every field they
    /// write; a field that does not fit is dropped, and the record's checks
    /// then fail, rather than panicking.
    fn put(&mut self, bytes: &[u8]) {
        let Some(end) = self.at.checked_add(bytes.len()) else {
            return;
        };
        if let Some(slot) = self.buffer.get_mut(self.at..end) {
            slot.copy_from_slice(bytes);
            self.at = end;
        }
    }

    /// The bytes written so far.
    fn written(&self) -> &[u8] {
        self.buffer.get(..self.at).unwrap_or_default()
    }
}

/// Reads fields from a byte slice, front to back, never past its end.
struct Reader<'a> {
    /// What is left to read.
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Starts reading at the front of `bytes`.
    const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// Takes the next `len` bytes.
    fn take(&mut self, len: usize) -> Result<&'a [u8], StoreError> {
        let (taken, rest) = self
            .rest
            .split_at_checked(len)
            .ok_or_else(|| corrupted("field runs past the end of its record".to_string()))?;
        self.rest = rest;
        Ok(taken)
    }

    /// Takes the next `N` bytes as an array.
    fn array<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        let (taken, rest) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or_else(|| corrupted("field runs past the end of its record".to_string()))?;
        self.rest = rest;
        Ok(*taken)
    }

    /// Takes a byte.
    fn u8(&mut self) -> Result<u8, StoreError> {
        self.array::<1>().map(|[byte]| byte)
    }

    /// Takes a little-endian u16.
    fn u16(&mut self) -> Result<u16, StoreError> {
        self.array().map(u16::from_le_bytes)
    }

    /// Takes a little-endian u32.
    fn u32(&mut self) -> Result<u32, StoreError> {
        self.array().map(u32::from_le_bytes)
    }

    /// Takes a little-endian u64.
    fn u64(&mut self) -> Result<u64, StoreError> {
        self.array().map(u64::from_le_bytes)
    }

    /// Takes everything that is left.
    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.rest)
    }
}

#[cfg(test)]
mod tests {
    //! The #78 format tests, ported from the version-1 reader to version-2
    //! record framing, and the tests of what version 2 adds (counter slots,
    //! generations, kind-5 records).

    use super::*;
    use std::io::Cursor;

    /// A generous body limit for the format tests.
    const MAX_BODY: u64 = 1024;

    /// The rule a store flushing every write uses.
    const EVERY_WRITE: DamageRule = DamageRule::Tail { records: 1 };

    /// Fails the test with context instead of `.unwrap()` / `.expect()`.
    #[track_caller]
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{what}: {err:?}"),
        }
    }

    fn header() -> Header {
        Header {
            creation_time: UNIX_EPOCH + Duration::new(1_760_000_000, 123_456_789),
            next_sender: 7,
            next_target: 9,
        }
    }

    fn slot(generation: u64, next_sender: u64, next_target: u64) -> Slot {
        Slot {
            generation,
            next_sender,
            next_target,
        }
    }

    fn slots(first: Slot, second: Slot) -> SlotImages {
        [encode_slot(&first), encode_slot(&second)]
    }

    /// The slots a new journal starts with: counters 7 and 9, generations 0
    /// and 1.
    fn fresh() -> SlotImages {
        ok(fresh_slots(0, 7, 9), "fresh slots").0
    }

    fn journal_with(slots: &SlotImages, records: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = encode_prefix(&header(), slots);
        for record in records {
            bytes.extend_from_slice(record);
        }
        bytes
    }

    fn journal(records: &[Vec<u8>]) -> Vec<u8> {
        journal_with(&fresh(), records)
    }

    fn scan_with(bytes: &[u8], rule: DamageRule) -> Result<Scan, StoreError> {
        scan(Cursor::new(bytes), bytes.len() as u64, MAX_BODY, rule)
    }

    fn scan_bytes(bytes: &[u8]) -> Result<Scan, StoreError> {
        scan_with(bytes, EVERY_WRITE)
    }

    /// A sealed frame record, kind 5 with `next` (taking `generation`), kind 1
    /// without.
    fn sealed(seq: u64, next: Option<u64>, generation: u64, frame: &[u8]) -> Vec<u8> {
        let mut record = ok(
            encode_frame_record(seq, next, &MsgType::NewOrderSingle, frame, 512),
            "frame record must encode",
        );
        seal_frame_record(&mut record, generation);
        record
    }

    fn frame(seq: u64, next: Option<u64>, frame: &[u8]) -> Vec<u8> {
        sealed(seq, next, seq + 1, frame)
    }

    fn seqs(scan: &Scan) -> Vec<u64> {
        scan.index.iter().map(|(seq, _)| seq).collect()
    }

    /// Re-seals a header after a test changed its bytes, so the check under
    /// test fails rather than the CRC.
    fn reseal_header(encoded: &mut [u8; HEADER_LEN]) {
        let crc = crc32(&encoded[..HEADER_LEN - 4]);
        encoded[HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
    }

    /// A journal of three frame records, and the offset of each record.
    fn three_frames() -> (Vec<u8>, [usize; 3]) {
        let records = [
            frame(1, None, b"one"),
            frame(2, None, b"two"),
            frame(3, None, b"three"),
        ];
        let first = DATA_START as usize;
        let second = first + records[0].len();
        let third = second + records[1].len();
        (journal(&records), [first, second, third])
    }

    /// Seals a hand-built body into a record.
    fn sealed_body(body: &[u8]) -> Vec<u8> {
        let mut record = vec![0u8; RECORD_HEADER_LEN];
        record.extend_from_slice(body);
        let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
        seal(&mut record, len);
        record
    }

    #[test]
    fn test_header_round_trips() {
        let encoded = encode_header(&header());
        assert_eq!(&encoded[..8], b"IRFXJRNL");
        assert_eq!(&encoded[8..10], &VERSION.to_le_bytes());
        assert_eq!(ok(decode_header(&encoded), "header must decode"), header());
    }

    #[test]
    fn test_header_with_wrong_magic_is_corrupted() {
        let mut encoded = encode_header(&header());
        encoded[0] = b'X';
        reseal_header(&mut encoded);
        assert!(matches!(
            decode_header(&encoded),
            Err(StoreError::Corrupted { reason }) if reason.contains("magic")
        ));
    }

    #[test]
    fn test_header_with_another_version_is_corrupted_naming_it() {
        for version in [1u16, 3] {
            let encoded = encode_versioned_header(&header(), version);
            assert!(matches!(
                decode_header(&encoded),
                Err(StoreError::Corrupted { reason })
                    if reason.contains(&format!("version {version} is not supported"))
            ));
        }
    }

    #[test]
    fn test_header_with_bad_crc_is_corrupted() {
        let mut encoded = encode_header(&header());
        encoded[30] ^= 0xFF;
        assert!(matches!(
            decode_header(&encoded),
            Err(StoreError::Corrupted { reason }) if reason.contains("checksum")
        ));
    }

    #[test]
    fn test_header_with_out_of_range_nanos_is_corrupted() {
        let mut encoded = encode_header(&header());
        encoded[20..24].copy_from_slice(&NANOS_PER_SECOND.to_le_bytes());
        reseal_header(&mut encoded);
        assert!(matches!(
            decode_header(&encoded),
            Err(StoreError::Corrupted { .. })
        ));
    }

    #[test]
    fn test_prefix_places_the_header_and_slots_in_their_blocks() {
        let images = fresh();
        let prefix = encode_prefix(&header(), &images);
        assert_eq!(prefix.len() as u64, DATA_START);
        assert_eq!(&prefix[..HEADER_LEN], &encode_header(&header()));
        assert_eq!(&prefix[4096..4096 + SLOT_LEN], &images[0]);
        assert_eq!(&prefix[8192..8192 + SLOT_LEN], &images[1]);
        assert!(prefix[HEADER_LEN..4096].iter().all(|byte| *byte == 0));
        assert!(prefix[4096 + SLOT_LEN..8192].iter().all(|byte| *byte == 0));
        assert!(prefix[8192 + SLOT_LEN..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn test_slot_round_trips_and_detects_damage() {
        let value = slot(9, 12, 40);
        let mut bytes = encode_slot(&value);
        assert_eq!(bytes.len(), SLOT_LEN);
        assert_eq!(decode_slot(&bytes), Some(value));
        bytes[3] ^= 0x10;
        assert_eq!(decode_slot(&bytes), None);
        assert_eq!(decode_slot(&[0u8; SLOT_LEN]), None, "zeros are not a slot");
    }

    #[test]
    fn test_newest_slot_picks_the_higher_generation_and_survives_one_torn_slot() {
        let old = slot(4, 7, 9);
        let new = slot(5, 7, 10);
        assert_eq!(ok(newest_slot(&slots(old, new)), "both"), (1, new));
        assert_eq!(ok(newest_slot(&slots(new, old)), "both"), (0, new));
        let mut torn = slots(old, new);
        torn[1][10] ^= 0xFF;
        assert_eq!(ok(newest_slot(&torn), "torn newest"), (0, old));
        torn[0][0] ^= 0xFF;
        assert!(matches!(
            newest_slot(&torn),
            Err(StoreError::Corrupted { reason }) if reason.contains("both counter slots")
        ));
        assert!(newest_slot(&slots(slot(5, 1, 1), new)).is_err());
        assert_eq!(ok(newest_slot(&slots(new, new)), "identical"), (0, new));
    }

    #[test]
    fn test_scan_replays_records_in_order() {
        let bytes = journal(&[
            frame(1, None, b"one"),
            frame(2, Some(3), b"two"),
            frame(1, None, b"uno"),
        ]);
        let scan = ok(scan_bytes(&bytes), "scan");
        assert_eq!(scan.header, header());
        assert_eq!(seqs(&scan), vec![1, 2]);
        // The kind-5 record (generation 3) is newer than the slots (0, 1).
        assert_eq!(scan.next_sender, 3);
        assert_eq!(scan.next_target, 9);
        assert_eq!(scan.end, bytes.len() as u64);
        assert_eq!(scan.truncation, None);

        // The later record for 1 replaced the earlier one.
        let Some(entry) = scan.index.get(1) else {
            panic!("1 must be indexed");
        };
        let message = ok(
            read_frame(&mut Cursor::new(&bytes), 1, entry),
            "read frame 1",
        );
        assert_eq!(&message.payload()[..], b"uno");
        assert_eq!(message.msg_type(), &MsgType::NewOrderSingle);
        assert_eq!(scan.dead_bytes, frame(1, None, b"one").len() as u64);
    }

    #[test]
    fn test_scan_of_a_journal_without_records_holds_the_slot_counters() {
        let bytes = journal_with(&slots(slot(3, 70, 90), slot(2, 1, 1)), &[]);
        let scan = ok(scan_bytes(&bytes), "scan");
        assert!(scan.index.is_empty());
        assert_eq!((scan.next_sender, scan.next_target), (70, 90));
        assert_eq!(scan.active, 0);
        assert_eq!(scan.next_generation, 4);
        assert_eq!(scan.end, DATA_START);
    }

    #[test]
    fn test_scan_takes_the_sender_from_the_newer_of_slot_and_record() {
        let records = [sealed(1, Some(2), 2, b"f"), sealed(2, Some(3), 3, b"f")];
        // Records newer than the slots carry the sender.
        let scan = ok(
            scan_bytes(&journal_with(
                &slots(slot(0, 1, 3), slot(1, 1, 3)),
                &records,
            )),
            "scan",
        );
        assert_eq!((scan.next_sender, scan.next_target), (3, 3));
        assert_eq!(scan.next_generation, 4);
        // A slot newer than the records (a lower number written back) wins.
        let scan = ok(
            scan_bytes(&journal_with(
                &slots(slot(4, 2, 3), slot(1, 1, 3)),
                &records,
            )),
            "scan",
        );
        assert_eq!(scan.next_sender, 2);
        assert_eq!(scan.active, 0);
        assert_eq!(scan.next_generation, 5);
    }

    #[test]
    fn test_scan_of_a_short_file_is_corrupted() {
        let bytes = journal(&[]);
        assert!(matches!(
            scan_bytes(&bytes[..HEADER_LEN - 1]),
            Err(StoreError::Corrupted { .. })
        ));
        assert!(matches!(
            scan_bytes(&bytes[..5000]),
            Err(StoreError::Corrupted { reason }) if reason.contains("12288")
        ));
    }

    #[test]
    fn test_scan_refuses_both_slots_damaged_whatever_the_rule() {
        let mut bytes = journal(&[frame(1, None, b"one")]);
        for offset in SLOT_OFFSETS {
            bytes[offset as usize + 2] ^= 0x01;
        }
        for rule in [EVERY_WRITE, DamageRule::Anywhere, DamageRule::Salvage] {
            assert!(matches!(
                scan_with(&bytes, rule),
                Err(StoreError::Corrupted { reason }) if reason.contains("both counter slots")
            ));
        }
    }

    #[test]
    fn test_scan_stops_at_a_record_cut_short() {
        let first = frame(1, Some(2), b"one");
        let second = frame(2, Some(3), b"two");
        let bytes = journal(&[first.clone(), second.clone()]);
        let good_end = DATA_START + first.len() as u64;
        // Every cut inside the second record, its header included.
        for cut in 1..second.len() {
            let torn = &bytes[..good_end as usize + cut];
            let scan = ok(scan_bytes(torn), "a torn tail is recovered, not an error");
            assert_eq!(scan.end, good_end, "cut at {cut}");
            assert_eq!(scan.next_sender, 2, "cut at {cut}");
            assert!(scan.index.get(2).is_none(), "cut at {cut}");
            assert_eq!(
                scan.truncation,
                Some(Truncation {
                    offset: good_end,
                    dropped_bytes: cut as u64,
                    cause: TruncationCause::Incomplete,
                }),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn test_scan_cuts_a_last_record_failing_its_crc() {
        let (mut bytes, [_, _, third]) = three_frames();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x20;
        let scan = ok(scan_bytes(&bytes), "a damaged last record is cut");
        assert_eq!(seqs(&scan), vec![1, 2]);
        assert_eq!(
            scan.truncation,
            Some(Truncation {
                offset: third as u64,
                dropped_bytes: (bytes.len() - third) as u64,
                cause: TruncationCause::Damaged,
            })
        );
    }

    #[test]
    fn test_scan_refuses_a_record_failing_its_crc_before_the_last() {
        let (mut bytes, [_, second, _]) = three_frames();
        // Flip a frame byte of record 2: record 3 was written after it.
        bytes[second + RECORD_HEADER_LEN + 12] ^= 0x20;
        assert!(matches!(
            scan_bytes(&bytes),
            Err(StoreError::Corrupted { reason })
                if reason.contains(&format!("offset {second}")) && reason.contains("repair")
        ));
        // A policy that leaves three writes unflushed cuts it instead.
        let scan = ok(
            scan_with(&bytes, DamageRule::Tail { records: 3 }),
            "within the unflushed window",
        );
        assert_eq!(seqs(&scan), vec![1]);
        // So does a policy that promises nothing, and a repair.
        for rule in [DamageRule::Anywhere, DamageRule::Salvage] {
            let scan = ok(scan_with(&bytes, rule), "cut anywhere");
            assert_eq!(
                scan.truncation.map(|cut| (cut.offset(), cut.cause())),
                Some((second as u64, TruncationCause::Damaged))
            );
        }
    }

    #[test]
    fn test_scan_cuts_a_crc_failure_followed_only_by_zeros() {
        let (mut bytes, [_, _, third]) = three_frames();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x20;
        // A file system can leave the file longer than what reached it.
        bytes.extend_from_slice(&[0u8; 5000]);
        let scan = ok(scan_bytes(&bytes), "zeros after the damage are cut");
        assert_eq!(scan.truncation.map(|cut| cut.offset()), Some(third as u64));
    }

    #[test]
    fn test_scan_cuts_a_zeroed_tail_of_any_length() {
        let mut bytes = journal(&[frame(1, None, b"one")]);
        // Far more than one maximum-size record, but no record is ever zeros.
        bytes.extend_from_slice(&[0u8; 3 * 1024 * 4]);
        let scan = ok(scan_bytes(&bytes), "zeroes are recovered, not an error");
        assert_eq!(
            scan.truncation.map(|cut| cut.cause()),
            Some(TruncationCause::Damaged)
        );
        assert_eq!(scan.index.len(), 1);
    }

    #[test]
    fn test_scan_damaged_record_header_is_cut_only_within_one_record_of_the_end() {
        let (bytes, [_, second, _]) = three_frames();
        // Garbage over record 2's header, with record 3 still behind it: the
        // remaining bytes fit one maximum-size record, so it may be a torn
        // write and is cut.
        let mut torn = bytes.clone();
        torn[second..second + 4].copy_from_slice(&[0xAB; 4]);
        let scan = ok(scan_bytes(&torn), "within one record of the end");
        assert_eq!(scan.truncation.map(|cut| cut.offset()), Some(second as u64));

        // The same damage with more than a maximum-size record behind it is
        // damage to written data.
        let mut damaged = bytes;
        damaged[second..second + 4].copy_from_slice(&[0xAB; 4]);
        for seq in 4..12 {
            damaged.extend_from_slice(&frame(seq, None, &[b'x'; 200]));
        }
        assert!(matches!(
            scan_bytes(&damaged),
            Err(StoreError::Corrupted { reason }) if reason.contains("damaged record header")
        ));
        assert!(scan_with(&damaged, DamageRule::Anywhere).is_ok());
    }

    #[test]
    fn test_scan_well_formed_length_above_the_limit_is_corrupted() {
        let mut bytes = journal(&[]);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&(!u32::MAX).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        // A short tail: had the length been trusted, reading it would have
        // asked for 4 GiB.
        bytes.extend_from_slice(b"tail");
        assert!(matches!(
            scan_bytes(&bytes),
            Err(StoreError::Corrupted { reason }) if reason.contains("4294967295")
        ));
        assert!(matches!(
            scan_with(&bytes, DamageRule::Anywhere),
            Err(StoreError::Corrupted { .. })
        ));
        // Only a repair cuts it.
        let scan = ok(scan_with(&bytes, DamageRule::Salvage), "salvage");
        assert_eq!(scan.truncation.map(|cut| cut.offset()), Some(DATA_START));
    }

    #[test]
    fn test_scan_well_formed_zero_length_is_corrupted() {
        let mut bytes = journal(&[]);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(!0u32).to_le_bytes());
        bytes.extend_from_slice(&crc32(b"").to_le_bytes());
        assert!(matches!(
            scan_bytes(&bytes),
            Err(StoreError::Corrupted { .. })
        ));
    }

    #[test]
    fn test_scan_unknown_record_kind_with_a_valid_crc_is_corrupted() {
        // Kind 4 was a version-1 counter record; version 2 does not know it.
        for kind in [2u8, 3, 4, 9] {
            let mut bytes = journal(&[]);
            bytes.extend_from_slice(&sealed_body(&[kind, 1, 2, 3, 4, 5, 6, 7, 8]));
            assert!(matches!(
                scan_bytes(&bytes),
                Err(StoreError::Corrupted { reason })
                    if reason.contains(&format!("unknown record kind {kind}"))
            ));
            let scan = ok(scan_with(&bytes, DamageRule::Salvage), "salvage");
            assert_eq!(
                scan.truncation.map(|cut| cut.cause()),
                Some(TruncationCause::Damaged)
            );
        }
    }

    #[test]
    fn test_scan_record_shorter_than_its_fields_is_corrupted() {
        // A kind-5 record cut off after its generation, with a valid CRC.
        let mut body = vec![KIND_FRAME_AND_SENDER];
        body.extend_from_slice(&1u64.to_le_bytes());
        body.extend_from_slice(&2u64.to_le_bytes());
        let mut bytes = journal(&[]);
        bytes.extend_from_slice(&sealed_body(&body));
        assert!(matches!(
            scan_bytes(&bytes),
            Err(StoreError::Corrupted { reason }) if reason.contains("shorter than its fields")
        ));
    }

    #[test]
    fn test_scan_frame_record_with_invalid_msg_type_is_corrupted() {
        let mut body = vec![KIND_FRAME];
        body.extend_from_slice(&1u64.to_le_bytes());
        body.push(2);
        body.extend_from_slice(&[0xFF, 0xFE]);
        body.extend_from_slice(b"frame");
        let mut bytes = journal(&[]);
        bytes.extend_from_slice(&sealed_body(&body));
        assert!(matches!(
            scan_bytes(&bytes),
            Err(StoreError::Corrupted { reason }) if reason.contains("invalid MsgType")
        ));
    }

    #[test]
    fn test_encode_frame_record_above_the_limit_is_store_failed() {
        let result = encode_frame_record(4, Some(5), &MsgType::NewOrderSingle, &[b'x'; 9], 8);
        assert!(matches!(
            result,
            Err(StoreError::StoreFailed { seq_num: 4, reason }) if !reason.contains("xxxx")
        ));
        // At the limit it encodes.
        assert!(encode_frame_record(4, Some(5), &MsgType::NewOrderSingle, &[b'x'; 8], 8).is_ok());
    }

    #[test]
    fn test_encode_frame_record_reserves_exactly_once_and_reuses_the_buffer() {
        let record = sealed(3, Some(4), 2, b"8=FIX.4.4\x0135=D\x01");
        // Header, kind, seq, generation, next sender, code length, "D", frame.
        assert_eq!(record.len(), 12 + 1 + 8 + 8 + 8 + 1 + 1 + 15);
        assert_eq!(record.capacity(), record.len());
        assert_eq!(record_body_len(&record) as usize, record.len() - 12);

        // A buffer already large enough is reused without growing.
        let mut buffer = Vec::with_capacity(256);
        let before = buffer.as_ptr();
        ok(
            encode_frame_record_into(&mut buffer, 3, None, &MsgType::Heartbeat, b"frame", 512),
            "encode into",
        );
        assert_eq!(buffer.as_ptr(), before);
        assert_eq!(buffer.capacity(), 256);
        assert_eq!(buffer.len(), 12 + 1 + 8 + 1 + 1 + 5);
    }

    #[test]
    fn test_seal_writes_the_generation_only_into_kind_five() {
        let record = sealed(4, Some(5), 77, b"frame");
        assert!(takes_generation(&record));
        assert_eq!(
            &record[GENERATION_AT..GENERATION_AT + 8],
            &77u64.to_le_bytes()
        );
        let plain = sealed(4, None, 77, b"frame");
        assert!(!takes_generation(&plain));
        assert_eq!(record.len(), plain.len() + 16);
        assert_eq!(MAX_BODY_OVERHEAD, 34);
    }

    #[test]
    fn test_read_frame_detects_a_record_changed_on_disk() {
        let record = frame(1, None, b"one");
        let mut bytes = journal(&[record]);
        let scan = ok(scan_bytes(&bytes), "scan");
        let Some(entry) = scan.index.get(1) else {
            panic!("1 must be indexed");
        };
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(matches!(
            read_frame(&mut Cursor::new(&bytes), 1, entry),
            Err(StoreError::Corrupted { reason }) if reason.contains("checksum")
        ));
        // Asking for another number at that offset is caught as well.
        bytes[last] ^= 0x01;
        assert!(matches!(
            read_frame(&mut Cursor::new(&bytes), 2, entry),
            Err(StoreError::Corrupted { .. })
        ));
        // And a file cut inside the record is damage, not an I/O error.
        assert!(matches!(
            read_frame(&mut Cursor::new(&bytes[..bytes.len() - 3]), 1, entry),
            Err(StoreError::Corrupted { reason }) if reason.contains("no longer whole")
        ));
    }

    #[test]
    fn test_read_record_into_reuses_the_buffer() {
        let bytes = journal(&[frame(1, None, b"one"), frame(2, None, b"two")]);
        let scan = ok(scan_bytes(&bytes), "scan");
        let mut buffer = Vec::with_capacity(512);
        let before = buffer.as_ptr();
        for (seq, entry) in scan.index.iter() {
            let (at, msg_type) = ok(
                read_record_into(&mut Cursor::new(&bytes), seq, entry, &mut buffer),
                "read",
            );
            assert_eq!(msg_type, MsgType::NewOrderSingle);
            assert_eq!(buffer.len() - at, 3);
        }
        assert_eq!(buffer.as_ptr(), before);
    }
}
