/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The on-disk format of a [`FileStore`](super::FileStore) journal, version 1.
//!
//! All integers are little-endian.
//!
//! # Header (44 bytes)
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 8 | magic, `IRFXJRNL` |
//! | 8 | 2 | format version, `1` |
//! | 10 | 2 | reserved, `0` |
//! | 12 | 8 | creation time, whole seconds since the Unix epoch |
//! | 20 | 4 | creation time, nanoseconds within the second |
//! | 24 | 8 | next sender `MsgSeqNum` the journal starts from |
//! | 32 | 8 | next target `MsgSeqNum` the journal starts from |
//! | 40 | 4 | CRC-32 of bytes 0..40 |
//!
//! # Records
//!
//! Records follow the header back to back until the end of the file. Each one
//! is a 12-byte record header and a body:
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
//! | 2, frame and next sender | `seq` u64, `next_sender` u64, `msg_type` length u8, `msg_type` bytes, frame bytes |
//! | 3, next sender | `next_sender` u64 |
//! | 4, next target | `next_target` u64 |
//!
//! Loading replays the records in file order: a later frame record for a
//! sequence number replaces an earlier one, and a later counter value replaces
//! an earlier one.

use crate::file::crc32::crc32;
use crate::stored::StoredMessage;
use bytes::Bytes;
use ironfix_core::error::StoreError;
use ironfix_core::message::{MSG_TYPE_MAX_LEN, MsgType};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The first eight bytes of every journal.
const MAGIC: [u8; 8] = *b"IRFXJRNL";

/// The format version this module reads and writes.
pub(crate) const FORMAT_VERSION: u16 = 1;

/// Length of the journal header, in bytes.
pub(crate) const HEADER_LEN: usize = 44;

/// Length of the journal header as a file offset, in bytes.
pub(crate) const HEADER_LEN_U64: u64 = 44;

/// Length of a record header, in bytes.
pub(crate) const RECORD_HEADER_LEN: usize = 12;

/// Length of a record header as a file offset, in bytes.
const RECORD_HEADER_LEN_U64: u64 = 12;

/// Largest part of a record body that is not frame bytes: the kind, the
/// sequence number, the next sender number, the `MsgType` length and the
/// longest `MsgType`.
pub(crate) const MAX_BODY_OVERHEAD: u64 = 1 + 8 + 8 + 1 + MSG_TYPE_MAX_LEN as u64;

/// Kind byte of a frame record.
const KIND_FRAME: u8 = 1;
/// Kind byte of a frame-and-next-sender record.
const KIND_FRAME_AND_SENDER: u8 = 2;
/// Kind byte of a next-sender record.
const KIND_NEXT_SENDER: u8 = 3;
/// Kind byte of a next-target record.
const KIND_NEXT_TARGET: u8 = 4;

/// Billion, the number of nanoseconds in a second.
const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// Why a [`FileStore`](super::FileStore) cut its journal short when it opened
/// or refreshed it.
///
/// Recovery never returns a record it cannot vouch for: the first record that
/// is incomplete or fails its checks is removed from the file, **together
/// with everything after it**, and the store carries on from the last good
/// record. See [`FileStore::last_truncation`](super::FileStore::last_truncation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TruncationCause {
    /// The file ends inside a record: a write was interrupted, which is what a
    /// crash during an append leaves. Only the interrupted write is lost.
    Incomplete,
    /// A record's header or body failed its check. A crash can leave this
    /// too, under a policy that does not flush every write, but so can damage
    /// to data already on disk: then records written, and acknowledged, after
    /// the damaged one are lost with it, and the counters they carried with
    /// them.
    Damaged,
}

/// A cut the store made to its journal while opening or refreshing it.
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

/// The fixed part of a journal: when it was created and the counters it
/// started from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    /// When the journal was created (by the first open or the last reset).
    pub(crate) creation_time: SystemTime,
    /// Next sender sequence number the journal starts from.
    pub(crate) next_sender: u64,
    /// Next target sequence number the journal starts from.
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

/// What a journal holds, as recovered by [`scan`].
#[derive(Debug)]
pub(crate) struct Scan {
    /// The journal header.
    pub(crate) header: Header,
    /// Every filed frame's record, by sequence number.
    pub(crate) index: BTreeMap<u64, IndexEntry>,
    /// The next sender sequence number after replaying every record.
    pub(crate) next_sender: u64,
    /// The next target sequence number after replaying every record.
    pub(crate) next_target: u64,
    /// File offset just past the last good record.
    pub(crate) end: u64,
    /// The cut recovery has to make, if any. The scan does not make it.
    pub(crate) truncation: Option<Truncation>,
}

/// One decoded record body.
#[derive(Debug, PartialEq, Eq)]
enum Record<'a> {
    /// A filed frame, with the next sender number when it was filed by
    /// `file_outbound`.
    Frame {
        /// The `MsgSeqNum` (34) it was filed under.
        seq: u64,
        /// The next sender number filed with it, if any.
        next_sender: Option<u64>,
        /// The `MsgType` (35) it was filed as.
        msg_type: MsgType,
        /// The frame bytes.
        frame: &'a [u8],
    },
    /// A next sender sequence number.
    NextSender(u64),
    /// A next target sequence number.
    NextTarget(u64),
}

/// Builds a [`StoreError::Corrupted`] for a reason.
#[cold]
#[inline(never)]
fn corrupted(reason: String) -> StoreError {
    StoreError::Corrupted { reason }
}

/// Builds a [`StoreError::Io`] for an I/O error, with what was being done.
#[cold]
#[inline(never)]
pub(crate) fn io_error(context: &str, err: &std::io::Error) -> StoreError {
    StoreError::Io(format!("{context}: {err}"))
}

/// Encodes a journal header.
#[must_use]
pub(crate) fn encode_header(header: &Header) -> [u8; HEADER_LEN] {
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
    out.put(&FORMAT_VERSION.to_le_bytes());
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
/// [`StoreError::Corrupted`] if the bytes are not a version-1 journal header.
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
    if version != FORMAT_VERSION {
        return Err(corrupted(format!(
            "journal format version {version} is not supported; this build reads version \
             {FORMAT_VERSION}"
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

/// Encodes a frame record: kind 1 without `next_sender`, kind 2 with it.
///
/// `max_frame_size` is the configured limit, in bytes.
///
/// # Errors
/// [`StoreError::StoreFailed`] if the frame is above `max_frame_size`. The
/// error never contains frame bytes.
pub(crate) fn encode_frame_record(
    seq: u64,
    next_sender: Option<u64>,
    msg_type: &MsgType,
    frame: &[u8],
    max_frame_size: u32,
) -> Result<Vec<u8>, StoreError> {
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
    let fixed: u32 = if next_sender.is_some() { 18 } else { 10 };
    let body_len = fixed
        .checked_add(u32::from(code_len))
        .and_then(|len| len.checked_add(frame_len))
        .ok_or_else(|| StoreError::StoreFailed {
            seq_num: seq,
            reason: "record length overflows".to_string(),
        })?;

    let mut body = Vec::with_capacity(RECORD_HEADER_LEN + body_len as usize);
    body.push(if next_sender.is_some() {
        KIND_FRAME_AND_SENDER
    } else {
        KIND_FRAME
    });
    body.extend_from_slice(&seq.to_le_bytes());
    if let Some(next_sender) = next_sender {
        body.extend_from_slice(&next_sender.to_le_bytes());
    }
    body.push(code_len);
    body.extend_from_slice(code);
    body.extend_from_slice(frame);
    Ok(seal(body, body_len))
}

/// Encodes a counter record.
#[must_use]
fn encode_counter_record(kind: u8, value: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(RECORD_HEADER_LEN + 9);
    body.push(kind);
    body.extend_from_slice(&value.to_le_bytes());
    seal(body, 9)
}

/// Encodes a next-sender record.
#[must_use]
pub(crate) fn encode_next_sender_record(next_sender: u64) -> Vec<u8> {
    encode_counter_record(KIND_NEXT_SENDER, next_sender)
}

/// Encodes a next-target record.
#[must_use]
pub(crate) fn encode_next_target_record(next_target: u64) -> Vec<u8> {
    encode_counter_record(KIND_NEXT_TARGET, next_target)
}

/// Prefixes `body` (of `body_len` bytes) with its record header.
#[must_use]
fn seal(body: Vec<u8>, body_len: u32) -> Vec<u8> {
    let mut record = Vec::with_capacity(RECORD_HEADER_LEN + body.len());
    record.extend_from_slice(&body_len.to_le_bytes());
    record.extend_from_slice(&(!body_len).to_le_bytes());
    record.extend_from_slice(&crc32(&body).to_le_bytes());
    record.extend_from_slice(&body);
    record
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
/// The reason the body is not a version-1 record, for the caller to place.
fn decode_body(body: &[u8]) -> Result<Record<'_>, String> {
    let mut input = Reader::new(body);
    let kind = input.u8().map_err(|_| "empty record body".to_string())?;
    let short = |_| format!("record of kind {kind} is shorter than its fields");
    match kind {
        KIND_FRAME | KIND_FRAME_AND_SENDER => {
            let seq = input.u64().map_err(short)?;
            let next_sender = if kind == KIND_FRAME_AND_SENDER {
                Some(input.u64().map_err(short)?)
            } else {
                None
            };
            let code_len = usize::from(input.u8().map_err(short)?);
            let code = input.take(code_len).map_err(short)?;
            let msg_type = std::str::from_utf8(code)
                .ok()
                .and_then(|code| MsgType::new(code).ok())
                .ok_or_else(|| format!("record for MsgSeqNum {seq} carries an invalid MsgType"))?;
            Ok(Record::Frame {
                seq,
                next_sender,
                msg_type,
                frame: input.rest(),
            })
        }
        KIND_NEXT_SENDER | KIND_NEXT_TARGET => {
            let value = input.u64().map_err(short)?;
            if !input.rest().is_empty() {
                return Err(format!("record of kind {kind} is longer than its fields"));
            }
            Ok(if kind == KIND_NEXT_SENDER {
                Record::NextSender(value)
            } else {
                Record::NextTarget(value)
            })
        }
        other => Err(format!("unknown record kind {other}")),
    }
}

/// Reads a journal from its start, `file_len` bytes long, and recovers what
/// it holds.
///
/// `max_body` is the largest record body the configuration allows, in bytes;
/// no more than that is ever allocated for one record.
///
/// The scan stops at the first record that is incomplete or fails its checks
/// and reports the cut in [`Scan::truncation`]; it does not modify the file.
///
/// # Errors
/// [`StoreError::Corrupted`] if the header is not a version-1 journal header,
/// if a record with a well-formed header declares a body of 0 bytes or above
/// `max_body`, or if a record that passes its CRC does not decode.
/// [`StoreError::Io`] if reading fails.
pub(crate) fn scan<R: Read>(
    mut reader: R,
    file_len: u64,
    max_body: u64,
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

    let mut scan = Scan {
        header,
        index: BTreeMap::new(),
        next_sender: header.next_sender,
        next_target: header.next_target,
        end: HEADER_LEN_U64,
        truncation: None,
    };
    let mut body = Vec::new();
    loop {
        let offset = scan.end;
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
        if remaining < RECORD_HEADER_LEN_U64 {
            scan.truncation = Some(cut(TruncationCause::Incomplete));
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
            scan.truncation = Some(cut(TruncationCause::Damaged));
            break;
        }
        if len == 0 || u64::from(len) > max_body {
            return Err(corrupted(format!(
                "record at offset {offset} declares a {len}-byte body; this store reads bodies \
                 of 1 to {max_body} bytes (was the journal written with a larger max frame size?)"
            )));
        }
        let record_len = RECORD_HEADER_LEN_U64 + u64::from(len);
        if remaining < record_len {
            scan.truncation = Some(cut(TruncationCause::Incomplete));
            break;
        }
        // Bounded by `max_body`, checked above.
        body.resize(len as usize, 0);
        reader
            .read_exact(&mut body)
            .map_err(|err| io_error("cannot read a journal record", &err))?;
        if crc32(&body) != crc {
            scan.truncation = Some(cut(TruncationCause::Damaged));
            break;
        }
        match decode_body(&body) {
            Ok(Record::Frame {
                seq, next_sender, ..
            }) => {
                scan.index.insert(
                    seq,
                    IndexEntry {
                        offset,
                        body_len: len,
                    },
                );
                if let Some(next_sender) = next_sender {
                    scan.next_sender = next_sender;
                }
            }
            Ok(Record::NextSender(value)) => scan.next_sender = value,
            Ok(Record::NextTarget(value)) => scan.next_target = value,
            Err(reason) => {
                return Err(corrupted(format!("record at offset {offset}: {reason}")));
            }
        }
        scan.end = offset
            .checked_add(record_len)
            .ok_or_else(|| corrupted("journal offset overflows".to_string()))?;
    }
    Ok(scan)
}

/// Reads the frame filed under `seq` from the record `entry` points at,
/// checking the record again on the way.
///
/// # Errors
/// [`StoreError::Corrupted`] if the record no longer matches the index or
/// fails its CRC (the disk changed under the store); [`StoreError::Io`] if
/// reading fails.
pub(crate) fn read_frame<F: Read + Seek>(
    file: &mut F,
    seq: u64,
    entry: IndexEntry,
) -> Result<StoredMessage, StoreError> {
    let IndexEntry { offset, body_len } = entry;
    let mismatch = |what: &str| {
        corrupted(format!(
            "record for MsgSeqNum {seq} at offset {offset} {what}"
        ))
    };
    file.seek(SeekFrom::Start(offset))
        .map_err(|err| io_error("cannot seek in the journal", &err))?;
    let mut record_header = [0u8; RECORD_HEADER_LEN];
    file.read_exact(&mut record_header)
        .map_err(|err| io_error("cannot read a journal record header", &err))?;
    let mut fields = Reader::new(&record_header);
    let len = fields.u32()?;
    let check = fields.u32()?;
    let crc = fields.u32()?;
    if len != body_len || check != !len {
        return Err(mismatch("no longer matches the index"));
    }
    // `body_len` was bounded by the configured limit when it was indexed.
    let mut body = vec![0u8; body_len as usize];
    file.read_exact(&mut body)
        .map_err(|err| io_error("cannot read a journal record", &err))?;
    if crc32(&body) != crc {
        return Err(mismatch("fails its checksum"));
    }
    let (msg_type, frame_at) = match decode_body(&body) {
        Ok(Record::Frame {
            seq: filed,
            msg_type,
            frame,
            ..
        }) if filed == seq => {
            // The frame is the tail of the body, so this never underflows.
            let at = body
                .len()
                .checked_sub(frame.len())
                .ok_or_else(|| mismatch("has a frame longer than its body"))?;
            (msg_type, at)
        }
        Ok(_) => return Err(mismatch("is not that message's frame")),
        Err(reason) => return Err(mismatch(&reason)),
    };
    Ok(StoredMessage::new(
        seq,
        msg_type,
        Bytes::from(body).slice(frame_at..),
    ))
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
    /// write; a field that does not fit is dropped, and the header CRC then
    /// fails, rather than panicking.
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
    use super::*;
    use std::io::Cursor;

    /// A generous body limit for the format tests.
    const MAX_BODY: u64 = 1024;

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

    fn journal(records: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = encode_header(&header()).to_vec();
        for record in records {
            bytes.extend_from_slice(record);
        }
        bytes
    }

    fn scan_bytes(bytes: &[u8]) -> Result<Scan, StoreError> {
        scan(Cursor::new(bytes), bytes.len() as u64, MAX_BODY)
    }

    fn frame(seq: u64, next: Option<u64>, frame: &[u8]) -> Vec<u8> {
        ok(
            encode_frame_record(seq, next, &MsgType::NewOrderSingle, frame, 512),
            "frame record must encode",
        )
    }

    #[test]
    fn test_header_round_trips() {
        let encoded = encode_header(&header());
        assert_eq!(&encoded[..8], b"IRFXJRNL");
        assert_eq!(ok(decode_header(&encoded), "header must decode"), header());
    }

    #[test]
    fn test_header_with_wrong_magic_is_corrupted() {
        let mut encoded = encode_header(&header());
        encoded[0] = b'X';
        // Re-seal so the magic check, not the CRC, is what fails.
        let crc = crc32(&encoded[..HEADER_LEN - 4]);
        encoded[HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            decode_header(&encoded),
            Err(StoreError::Corrupted { reason }) if reason.contains("magic")
        ));
    }

    #[test]
    fn test_header_with_unknown_version_is_corrupted() {
        let mut encoded = encode_header(&header());
        encoded[8..10].copy_from_slice(&2u16.to_le_bytes());
        let crc = crc32(&encoded[..HEADER_LEN - 4]);
        encoded[HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            decode_header(&encoded),
            Err(StoreError::Corrupted { reason }) if reason.contains("version 2")
        ));
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
        let crc = crc32(&encoded[..HEADER_LEN - 4]);
        encoded[HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            decode_header(&encoded),
            Err(StoreError::Corrupted { .. })
        ));
    }

    #[test]
    fn test_scan_replays_records_in_order() {
        let bytes = journal(&[
            frame(1, None, b"one"),
            frame(2, Some(3), b"two"),
            encode_next_target_record(5),
            frame(1, None, b"uno"),
            encode_next_sender_record(4),
        ]);
        let scan = ok(scan_bytes(&bytes), "scan");
        assert_eq!(scan.header, header());
        assert_eq!(scan.index.keys().copied().collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(scan.next_sender, 4);
        assert_eq!(scan.next_target, 5);
        assert_eq!(scan.end, bytes.len() as u64);
        assert_eq!(scan.truncation, None);

        // The later record for 1 replaced the earlier one.
        let entry = scan.index.get(&1).copied();
        let Some(entry) = entry else {
            panic!("1 must be indexed");
        };
        let message = ok(
            read_frame(&mut Cursor::new(&bytes), 1, entry),
            "read frame 1",
        );
        assert_eq!(&message.payload()[..], b"uno");
        assert_eq!(message.msg_type(), &MsgType::NewOrderSingle);
    }

    #[test]
    fn test_scan_of_a_header_only_journal_holds_the_header_counters() {
        let bytes = journal(&[]);
        let scan = ok(scan_bytes(&bytes), "scan");
        assert!(scan.index.is_empty());
        assert_eq!((scan.next_sender, scan.next_target), (7, 9));
        assert_eq!(scan.end, HEADER_LEN_U64);
    }

    #[test]
    fn test_scan_of_a_short_file_is_corrupted() {
        let bytes = journal(&[]);
        assert!(matches!(
            scan_bytes(&bytes[..HEADER_LEN - 1]),
            Err(StoreError::Corrupted { .. })
        ));
    }

    #[test]
    fn test_scan_stops_at_a_record_cut_short() {
        let first = frame(1, Some(2), b"one");
        let second = frame(2, Some(3), b"two");
        let bytes = journal(&[first.clone(), second.clone()]);
        let good_end = (HEADER_LEN + first.len()) as u64;
        // Every cut inside the second record, its header included.
        for cut in 1..second.len() {
            let torn = &bytes[..HEADER_LEN + first.len() + cut];
            let scan = ok(scan_bytes(torn), "a torn tail is recovered, not an error");
            assert_eq!(scan.end, good_end, "cut at {cut}");
            assert_eq!(scan.next_sender, 2, "cut at {cut}");
            assert!(!scan.index.contains_key(&2), "cut at {cut}");
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
    fn test_scan_stops_at_a_body_failing_its_crc() {
        let first = frame(1, None, b"one");
        let mut bytes = journal(&[first.clone(), frame(2, None, b"two"), frame(3, None, b"3")]);
        // Flip a frame byte of record 2.
        let at = HEADER_LEN + first.len() + RECORD_HEADER_LEN + 12;
        bytes[at] ^= 0x20;
        let scan = ok(scan_bytes(&bytes), "damage is recovered, not an error");
        assert_eq!(scan.index.keys().copied().collect::<Vec<_>>(), vec![1]);
        let good_end = (HEADER_LEN + first.len()) as u64;
        assert_eq!(
            scan.truncation,
            Some(Truncation {
                offset: good_end,
                dropped_bytes: bytes.len() as u64 - good_end,
                cause: TruncationCause::Damaged,
            })
        );
    }

    #[test]
    fn test_scan_stops_at_a_zeroed_record_header() {
        let mut bytes = journal(&[frame(1, None, b"one")]);
        bytes.extend_from_slice(&[0u8; 64]);
        let scan = ok(scan_bytes(&bytes), "zeroes are recovered, not an error");
        assert_eq!(
            scan.truncation.map(|cut| cut.cause()),
            Some(TruncationCause::Damaged)
        );
        assert_eq!(scan.index.len(), 1);
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
        let mut bytes = journal(&[]);
        bytes.extend_from_slice(&seal(vec![9, 1, 2, 3], 4));
        assert!(matches!(
            scan_bytes(&bytes),
            Err(StoreError::Corrupted { reason }) if reason.contains("unknown record kind 9")
        ));
    }

    #[test]
    fn test_scan_counter_record_with_trailing_bytes_is_corrupted() {
        let mut bytes = journal(&[]);
        let mut body = vec![KIND_NEXT_TARGET];
        body.extend_from_slice(&5u64.to_le_bytes());
        body.push(0);
        bytes.extend_from_slice(&seal(body, 10));
        assert!(matches!(
            scan_bytes(&bytes),
            Err(StoreError::Corrupted { .. })
        ));
    }

    #[test]
    fn test_scan_frame_record_with_invalid_msg_type_is_corrupted() {
        let mut bytes = journal(&[]);
        let mut body = vec![KIND_FRAME];
        body.extend_from_slice(&1u64.to_le_bytes());
        body.push(2);
        body.extend_from_slice(&[0xFF, 0xFE]);
        body.extend_from_slice(b"frame");
        let len = body.len() as u32;
        bytes.extend_from_slice(&seal(body, len));
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
    fn test_read_frame_detects_a_record_changed_on_disk() {
        let record = frame(1, None, b"one");
        let mut bytes = journal(&[record]);
        let scan = ok(scan_bytes(&bytes), "scan");
        let Some(entry) = scan.index.get(&1).copied() else {
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
    }

    #[test]
    fn test_record_body_len_reads_the_length_field() {
        let record = encode_next_sender_record(3);
        assert_eq!(record_body_len(&record), 9);
        assert_eq!(record.len(), RECORD_HEADER_LEN + 9);
        assert_eq!(MAX_BODY_OVERHEAD, 26);
    }
}
