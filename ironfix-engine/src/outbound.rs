/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Outbound message builder and the rules an outbound body must satisfy.
//!
//! [`OutboundMessage`] is the **pre-encoding form of every message the engine
//! sends** — application messages handed to
//! [`Connection::send`](crate::Connection::send) and the administrative
//! messages the session layer builds for itself. It is what
//! [`Application::to_app_checked`](crate::Application::to_app_checked) (by
//! default, [`Application::to_app`](crate::Application::to_app)) and
//! [`Application::to_admin`](crate::Application::to_admin) receive, and it is
//! what the engine encodes, so a mutation made in a callback reaches the wire.
//!
//! # What a body may not carry
//!
//! The engine stamps the standard header and trailer itself. A body field that
//! repeats one of those tags produces a frame with two occurrences of it, which
//! a conforming counterparty rejects or misparses, so [`RESERVED_TAGS`] are
//! refused at the public boundary rather than duplicated. Administrative
//! MsgTypes are refused there too: Logon, Logout, SequenceReset and the rest
//! belong to the session state machine, and one emitted behind its back leaves
//! the engine's phase tracking describing a session that no longer exists.
//!
//! # Pooled messages
//!
//! [`Connection::acquire`](crate::Connection::acquire) hands out an
//! [`OutboundMessage`] drawn from the session's bounded pool. It is an
//! ordinary `OutboundMessage` in every respect but one: when it is dropped,
//! wherever that happens (in the session after its frame is written or it is
//! refused, or in the caller's hands without ever being sent), it goes back
//! to the pool with its field list and value buffers emptied but not freed.
//! The next message acquired reuses them, so a body built with the copying
//! push methods ([`OutboundMessage::push_str`], [`OutboundMessage::push_bytes`],
//! [`OutboundMessage::push_int`], [`OutboundMessage::push_uint`],
//! [`OutboundMessage::push_char`], [`OutboundMessage::push_bool`]) allocates
//! nothing once the pool is warm. [`OutboundMessage::push_raw`] and
//! [`OutboundMessage::push_data`] take a value the caller already allocated,
//! so they do not benefit. See `doc/adr/0008-pooled-outbound-messages.md`.
//!
//! The pool is bounded and never blocks: when it is empty, `acquire` builds
//! a fresh message, and a message returned to a full pool is freed. What a
//! pooled message retains is bounded too (see [`POOLED_MAX_FIELDS`],
//! [`POOLED_MAX_SPARE`] and [`POOLED_MAX_VALUE_BYTES`]).

use crate::error::EngineError;
use ironfix_core::message::MsgType;
use ironfix_tagvalue::SOH;
use std::sync::{Arc, Mutex, PoisonError};

/// The most body fields a pooled message may have room for and still go back
/// to its pool: a message whose field list grew beyond this is freed when it
/// is dropped, so one unusually large body cannot pin its memory in the pool.
pub const POOLED_MAX_FIELDS: usize = 256;

/// The most emptied value buffers a message keeps for reuse.
pub const POOLED_MAX_SPARE: usize = 256;

/// The largest value buffer, in bytes of capacity, a message keeps for
/// reuse; a larger one is freed when its field is cleared or removed.
pub const POOLED_MAX_VALUE_BYTES: usize = 1024;

/// A single body field of an [`OutboundMessage`], in the form the encoder
/// needs to stamp it.
///
/// Most fields are [`OutboundField::Raw`] and are written verbatim. A FIX
/// `DATA` field (`RawData`/96, `Signature`/89, the `Encoded*` family) legally
/// contains the SOH delimiter and `=`, so it is decodable only alongside its
/// paired `LENGTH` field; those fields are [`OutboundField::Data`] and are
/// emitted as a counted pair so the payload's SOH bytes are never read as field
/// terminators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundField {
    /// An ordinary field, written as `tag=value<SOH>`.
    Raw {
        /// The field tag number.
        tag: u32,
        /// The field value bytes.
        value: Vec<u8>,
    },
    /// A counted `LENGTH`/`DATA` pair, written as
    /// `length_tag=<value.len()><SOH>data_tag=<value><SOH>`.
    Data {
        /// The `LENGTH` field tag (e.g., 95 `RawDataLength`).
        length_tag: u32,
        /// The paired `DATA` field tag (e.g., 96 `RawData`).
        data_tag: u32,
        /// The raw payload, which may carry SOH and `=`.
        value: Vec<u8>,
    },
}

/// Tags the engine stamps into the standard header or trailer itself.
///
/// In order: `BeginString` (8), `BodyLength` (9), `CheckSum` (10),
/// `MsgSeqNum` (34), `MsgType` (35), `PossDupFlag` (43), `SenderCompID` (49),
/// `SenderSubID` (50), `SendingTime` (52), `TargetCompID` (56),
/// `TargetSubID` (57), `OrigSendingTime` (122) and `ApplVerID` (1128).
///
/// A body carrying any of them is refused with [`EngineError::ReservedTag`].
pub const RESERVED_TAGS: [u32; 13] = [8, 9, 10, 34, 35, 43, 49, 50, 52, 56, 57, 122, 1128];

/// Tags whose values may carry a credential and must never appear in a log.
///
/// In order: `RawData` (96), `Password` (554) and `NewPassword` (925). The
/// [`Debug`] impl of [`OutboundMessage`] replaces their values with a redaction
/// marker so that logging the message — the object a `to_admin` callback stamps
/// a password onto — cannot leak a secret.
const SENSITIVE_TAGS: [u32; 3] = [96, 554, 925];

/// Body tags an administrative MsgType may not go out without.
///
/// The engine's [`MessageFactory`](crate::wire::MessageFactory) always builds
/// these in, but `to_admin` receives the message by `&mut` and can
/// [`remove`](OutboundMessage::remove) them. A Logon stripped of `HeartBtInt`
/// (108) or a TestRequest stripped of `TestReqID` (112) is malformed, and every
/// conforming counterparty rejects it — so the drop is caught here rather than
/// emitted. Header and trailer tags are covered separately by [`RESERVED_TAGS`].
///
/// The lookup is by wire code so a [`MsgType::Custom`] holding an administrative
/// code is protected the same way. `Password` (554) and the rest are optional
/// on the wire and are not listed. Returns an empty slice for every application
/// MsgType and for administrative types with no required body field (Heartbeat,
/// Logout).
fn admin_required_tags(msg_type: &MsgType) -> &'static [u32] {
    match msg_type.as_str() {
        "A" => &[98, 108], // Logon: EncryptMethod, HeartBtInt.
        "1" => &[112],     // TestRequest: TestReqID.
        "2" => &[7, 16],   // ResendRequest: BeginSeqNo, EndSeqNo.
        "4" => &[36],      // SequenceReset: NewSeqNo.
        _ => &[],
    }
}

/// Checks that a message may be sent on the application path.
///
/// Enforces the two rules the public boundary owns: the MsgType must not be
/// administrative, and the body must not repeat a tag the engine stamps.
///
/// # Errors
/// [`EngineError::ReservedMsgType`] for an administrative MsgType, otherwise
/// whatever [`check_body`] reports.
pub(crate) fn check_sendable(message: &OutboundMessage) -> Result<(), EngineError> {
    if message.msg_type().is_admin() {
        return Err(EngineError::ReservedMsgType {
            msg_type: message.msg_type().as_str().to_string(),
        });
    }
    check_body(message)
}

/// Checks that every body field has a legal wire form, is not one the engine
/// stamps itself, and — for an administrative MsgType — that no field the
/// message cannot go out without has been dropped.
///
/// Run again after `to_admin` / `to_app`, because a callback can append fields
/// the caller never wrote and can [`remove`](OutboundMessage::remove) fields the
/// session layer built in.
///
/// # Errors
/// [`EngineError::ReservedTag`] for a tag in [`RESERVED_TAGS`],
/// [`EngineError::InvalidField`] for tag `0`, an empty value, or a value
/// carrying the SOH delimiter — which would terminate its own field early and
/// let the remainder inject further fields into the frame — and
/// [`EngineError::MissingRequiredField`] when an administrative message no
/// longer carries a tag in [`admin_required_tags`].
///
/// The reported reason never quotes the value: an outbound Logon body carries
/// `Password` (554) and `NewPassword` (925).
pub(crate) fn check_body(message: &OutboundMessage) -> Result<(), EngineError> {
    for field in message.fields() {
        match field {
            OutboundField::Raw { tag, value } => {
                check_body_tag(*tag)?;
                if value.is_empty() {
                    return Err(EngineError::InvalidField {
                        tag: *tag,
                        reason: "value is empty; a FIX field carries at least one byte".to_string(),
                    });
                }
                if value.contains(&SOH) {
                    return Err(EngineError::InvalidField {
                        tag: *tag,
                        reason:
                            "value contains the SOH delimiter, which would terminate the field \
                                 early and inject the remainder as further fields"
                                .to_string(),
                    });
                }
            }
            // A DATA field legally carries the SOH delimiter and `=`: it is
            // framed as a counted LENGTH/DATA pair, so the payload's bytes are
            // never read as field terminators and are not checked for SOH here.
            // Both tags are still the engine's to refuse if reserved or zero.
            OutboundField::Data {
                length_tag,
                data_tag,
                ..
            } => {
                check_body_tag(*length_tag)?;
                check_body_tag(*data_tag)?;
            }
        }
    }
    // An administrative message that lost a required body field — a `to_admin`
    // that removed HeartBtInt (108) from a Logon, say — must not reach the wire:
    // the counterparty rejects it and the session's own handshake stalls.
    for &required in admin_required_tags(message.msg_type()) {
        if message.get(required).is_none() {
            return Err(EngineError::MissingRequiredField {
                msg_type: message.msg_type().as_str().to_string(),
                tag: required,
            });
        }
    }
    Ok(())
}

/// Refuses a body tag that is `0` (no such FIX tag) or one the engine stamps
/// into the standard header or trailer itself.
///
/// # Errors
/// [`EngineError::InvalidField`] for tag `0`, [`EngineError::ReservedTag`] for a
/// tag in [`RESERVED_TAGS`].
fn check_body_tag(tag: u32) -> Result<(), EngineError> {
    if tag == 0 {
        return Err(EngineError::InvalidField {
            tag,
            reason: "0 is not a legal FIX field tag: tags are positive integers starting at 1"
                .to_string(),
        });
    }
    if RESERVED_TAGS.contains(&tag) {
        return Err(EngineError::ReservedTag { tag });
    }
    Ok(())
}

/// An outbound message: a MsgType plus ordered body fields.
///
/// The engine stamps the standard header (BeginString, BodyLength, MsgType,
/// SenderCompID, TargetCompID, MsgSeqNum, SendingTime) and the trailer when
/// the message is sent, so the builder only carries body fields. Fields are
/// encoded in insertion order.
///
/// # Mutating one in a callback
///
/// [`Application::to_admin`](crate::Application::to_admin) and
/// [`Application::to_app_checked`](crate::Application::to_app_checked) (by
/// default, [`Application::to_app`](crate::Application::to_app)) receive this
/// type by `&mut` **before** the header is stamped and before a sequence
/// number is spent, so a field added there is encoded into the frame that
/// goes out, and a message `to_app_checked` vetoes costs nothing. The
/// canonical use is stamping `Username` (553) and `Password` (554) onto the
/// outbound Logon.
///
/// The header fields are not visible here — in particular `MsgSeqNum` (34) is
/// not yet decided when the callback runs, which is what lets a rejected
/// message cost nothing.
///
/// # Constraints
///
/// [`OutboundMessage::new`] accepts any MsgType so the engine can build its own
/// administrative messages with it; the restriction to application MsgTypes is
/// enforced by [`Connection::send`](crate::Connection::send), which is the
/// public path. See [`RESERVED_TAGS`] for the tags a body may not carry.
///
/// # Credentials never print
///
/// This is the object a `to_admin` callback stamps a `Password` (554) onto, so
/// its [`Debug`] impl is hand-written to redact the values of `Password` (554),
/// `NewPassword` (925) and `RawData` (96) — a derived `Debug` would let a single
/// `tracing::debug!(?message)` leak a secret. Every other field is shown as
/// normal.
pub struct OutboundMessage {
    /// Message type (tag 35).
    msg_type: MsgType,
    /// Body fields in insertion order.
    fields: Vec<OutboundField>,
    /// Emptied value buffers, reused by the copying push methods before any
    /// new buffer is allocated. Empty on a message that never cleared one.
    spare: Vec<Vec<u8>>,
    /// The pool this message returns to when dropped; `None` for a message
    /// built with [`OutboundMessage::new`] and for a clone.
    pool: Option<Arc<OutboundPool>>,
}

impl Clone for OutboundMessage {
    /// Clones the type and the body. The clone is not pooled and carries no
    /// spare buffers: it is freed when dropped, as a message built with
    /// [`OutboundMessage::new`] is.
    fn clone(&self) -> Self {
        Self {
            msg_type: self.msg_type.clone(),
            fields: self.fields.clone(),
            spare: Vec::new(),
            pool: None,
        }
    }
}

impl Drop for OutboundMessage {
    /// Returns a pooled message to its pool, its body cleared and its storage
    /// kept; frees any other message as usual.
    fn drop(&mut self) {
        let Some(pool) = self.pool.take() else {
            return;
        };
        if self.fields.capacity() > POOLED_MAX_FIELDS {
            return;
        }
        let mut recycled = Self {
            msg_type: MsgType::Heartbeat,
            fields: std::mem::take(&mut self.fields),
            spare: std::mem::take(&mut self.spare),
            pool: None,
        };
        recycled.clear();
        pool.give_back(recycled);
    }
}

/// Keeps an emptied value buffer in `spare` for reuse, within the pooled
/// bounds, and frees it otherwise.
fn keep_spare(spare: &mut Vec<Vec<u8>>, mut value: Vec<u8>) {
    if spare.len() < POOLED_MAX_SPARE && value.capacity() <= POOLED_MAX_VALUE_BYTES {
        value.clear();
        spare.push(value);
    }
}

/// A session's bounded pool of idle [`OutboundMessage`]s, behind
/// [`Connection::acquire`](crate::Connection::acquire).
///
/// Never blocks and never fails: an empty pool builds a fresh message, and a
/// full one frees the message handed back. The lock guards a `Vec` pop or
/// push, a short synchronous critical section never held across an `.await`.
#[derive(Debug)]
pub(crate) struct OutboundPool {
    /// Idle messages, cleared, not tied to a pool themselves.
    idle: Mutex<Vec<OutboundMessage>>,
    /// The most idle messages kept.
    capacity: usize,
}

impl OutboundPool {
    /// Builds an empty pool keeping at most `capacity` idle messages (at
    /// least one).
    #[must_use]
    pub(crate) fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            idle: Mutex::new(Vec::new()),
            capacity: capacity.max(1),
        })
    }

    /// Takes an idle message, or builds a fresh one when none is idle, and
    /// ties it to this pool.
    #[must_use]
    pub(crate) fn acquire(self: &Arc<Self>, msg_type: MsgType) -> OutboundMessage {
        // A poisoned lock means a holder panicked around a pop or a push of
        // whole values: the list is still a list of cleared messages.
        let recycled = self
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        let mut message = match recycled {
            Some(message) => message,
            None => OutboundMessage::new(msg_type.clone()),
        };
        message.msg_type = msg_type;
        message.pool = Some(Arc::clone(self));
        message
    }

    /// Keeps a cleared message for the next [`OutboundPool::acquire`], or
    /// frees it, outside the lock, when the pool is full.
    fn give_back(&self, message: OutboundMessage) {
        let overflow = {
            let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
            if idle.len() < self.capacity {
                idle.push(message);
                None
            } else {
                Some(message)
            }
        };
        drop(overflow);
    }

    /// How many idle messages the pool holds.
    #[cfg(test)]
    pub(crate) fn idle(&self) -> usize {
        self.idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl std::fmt::Debug for OutboundMessage {
    /// Redacts the value of every credential-bearing field so the type cannot
    /// leak a `Password` (554), `NewPassword` (925) or `RawData` (96) through a
    /// log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        /// Renders the body list, redacting the values of sensitive tags.
        struct RedactedFields<'a>(&'a [OutboundField]);
        impl std::fmt::Debug for RedactedFields<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let mut list = f.debug_list();
                for field in self.0 {
                    match field {
                        OutboundField::Raw { tag, value } => {
                            if SENSITIVE_TAGS.contains(tag) {
                                list.entry(&(tag, "<redacted>"));
                            } else {
                                list.entry(&(tag, &String::from_utf8_lossy(value)));
                            }
                        }
                        OutboundField::Data {
                            length_tag,
                            data_tag,
                            value,
                        } => {
                            if SENSITIVE_TAGS.contains(data_tag) {
                                list.entry(&(length_tag, data_tag, "<redacted>"));
                            } else {
                                list.entry(&(
                                    length_tag,
                                    data_tag,
                                    &String::from_utf8_lossy(value),
                                ));
                            }
                        }
                    }
                }
                list.finish()
            }
        }
        f.debug_struct("OutboundMessage")
            .field("msg_type", &self.msg_type)
            .field("fields", &RedactedFields(&self.fields))
            .finish()
    }
}

impl OutboundMessage {
    /// Creates a new outbound message of the given type.
    ///
    /// # Arguments
    /// * `msg_type` - The message type (tag 35)
    #[must_use]
    pub fn new(msg_type: MsgType) -> Self {
        Self {
            msg_type,
            fields: Vec::new(),
            spare: Vec::new(),
            pool: None,
        }
    }

    /// Returns true if this message came from
    /// [`Connection::acquire`](crate::Connection::acquire) and goes back to
    /// the session's pool when dropped.
    #[must_use]
    pub const fn is_pooled(&self) -> bool {
        self.pool.is_some()
    }

    /// A value buffer with room for `len` bytes: an emptied spare one when
    /// there is one, a new one otherwise.
    ///
    /// A spare buffer grows to exactly `len`, never by doubling: a doubled
    /// buffer could pass [`POOLED_MAX_VALUE_BYTES`] for a value that fits it,
    /// be freed when recycled, and be allocated again on every reuse.
    fn buffer(&mut self, len: usize) -> Vec<u8> {
        match self.spare.pop() {
            Some(mut buffer) => {
                buffer.reserve_exact(len);
                buffer
            }
            None => Vec::with_capacity(len),
        }
    }

    /// Keeps the emptied value buffer of a field taken out of the body, within
    /// the pooled bounds, and frees it otherwise.
    fn recycle(&mut self, field: OutboundField) {
        let (OutboundField::Raw { value, .. } | OutboundField::Data { value, .. }) = field;
        keep_spare(&mut self.spare, value);
    }

    /// Removes every body field, keeping the field list's room and, within
    /// the pooled bounds, the value buffers for the next fields pushed.
    ///
    /// The buffers are kept last field first, so the next body pushed takes
    /// them back in field order: a message refilled with the same layout gets
    /// each field's own buffer, already large enough, and never regrows one.
    fn clear(&mut self) {
        let mut fields = std::mem::take(&mut self.fields);
        for field in fields.drain(..).rev() {
            self.recycle(field);
        }
        self.fields = fields;
    }

    /// Returns the message type.
    #[must_use]
    pub fn msg_type(&self) -> &MsgType {
        &self.msg_type
    }

    /// Appends a field with raw bytes.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value bytes
    pub fn push_raw(&mut self, tag: u32, value: impl Into<Vec<u8>>) -> &mut Self {
        self.fields.push(OutboundField::Raw {
            tag,
            value: value.into(),
        });
        self
    }

    /// Appends a counted `LENGTH`/`DATA` field pair.
    ///
    /// A FIX `DATA` field (`RawData`/96, `Signature`/89, the `Encoded*` family)
    /// legally contains SOH and `=`; it is decodable only because its paired
    /// `LENGTH` field declares its byte count. The engine derives that count
    /// from `value` when the message is encoded, so the two cannot disagree and
    /// the payload's SOH bytes are never read as field terminators. Use this
    /// instead of [`OutboundMessage::push_raw`] for any `DATA` field —
    /// `push_raw` refuses a `LENGTH` or `DATA` tag precisely because writing one
    /// half alone would corrupt the frame.
    ///
    /// # Arguments
    /// * `length_tag` - The `LENGTH` field tag (e.g., 95 `RawDataLength`)
    /// * `data_tag` - The paired `DATA` field tag (e.g., 96 `RawData`)
    /// * `value` - The raw payload
    pub fn push_data(
        &mut self,
        length_tag: u32,
        data_tag: u32,
        value: impl Into<Vec<u8>>,
    ) -> &mut Self {
        self.fields.push(OutboundField::Data {
            length_tag,
            data_tag,
            value: value.into(),
        });
        self
    }

    /// Appends a field with a string value.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value
    pub fn push_str(&mut self, tag: u32, value: &str) -> &mut Self {
        self.push_bytes(tag, value.as_bytes())
    }

    /// Appends a field with raw bytes, copying `value`.
    ///
    /// Unlike [`OutboundMessage::push_raw`], which takes ownership of a value
    /// the caller already allocated, this copies into a value buffer the
    /// message kept from an earlier field when it has one, so on a pooled
    /// message (see [`Connection::acquire`](crate::Connection::acquire)) it
    /// allocates nothing once the pool is warm.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value bytes
    pub fn push_bytes(&mut self, tag: u32, value: &[u8]) -> &mut Self {
        let mut buffer = self.buffer(value.len());
        buffer.extend_from_slice(value);
        self.fields.push(OutboundField::Raw { tag, value: buffer });
        self
    }

    /// Appends a field holding the decimal form of an integer, written
    /// straight into a value buffer.
    fn push_decimal(&mut self, tag: u32, value: impl std::fmt::Display) -> &mut Self {
        use std::io::Write as _;
        // 20 bytes hold every u64 and every i64, sign included, so the write
        // never grows the buffer; writing into a Vec cannot fail.
        let mut buffer = self.buffer(20);
        let _ = write!(buffer, "{value}");
        self.fields.push(OutboundField::Raw { tag, value: buffer });
        self
    }

    /// Appends a field with an integer value.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value
    pub fn push_int(&mut self, tag: u32, value: i64) -> &mut Self {
        self.push_decimal(tag, value)
    }

    /// Appends a field with an unsigned integer value.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value
    pub fn push_uint(&mut self, tag: u32, value: u64) -> &mut Self {
        self.push_decimal(tag, value)
    }

    /// Appends a field with a single character value.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value
    pub fn push_char(&mut self, tag: u32, value: char) -> &mut Self {
        let mut buf = [0u8; 4];
        let s = value.encode_utf8(&mut buf);
        self.push_bytes(tag, s.as_bytes())
    }

    /// Appends a field with a boolean value (Y/N).
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value
    pub fn push_bool(&mut self, tag: u32, value: bool) -> &mut Self {
        self.push_bytes(tag, if value { b"Y" } else { b"N" })
    }

    /// Returns the value of the first field with `tag`, if present.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    #[must_use]
    pub fn get(&self, tag: u32) -> Option<&[u8]> {
        self.fields.iter().find_map(|field| match field {
            OutboundField::Raw {
                tag: field_tag,
                value,
            } if *field_tag == tag => Some(value.as_slice()),
            OutboundField::Data {
                data_tag, value, ..
            } if *data_tag == tag => Some(value.as_slice()),
            _ => None,
        })
    }

    /// Removes every field carrying `tag`, returning how many were removed.
    ///
    /// A [`OutboundField::Data`] pair is removed when either its `LENGTH` or its
    /// `DATA` tag matches, so the counted halves never survive apart. The
    /// removed values' buffers are kept for the next fields pushed.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    pub fn remove(&mut self, tag: u32) -> usize {
        // One linear pass that keeps the order of the fields left; a removed
        // field's buffer is moved out (leaving an empty, unallocated `Vec`)
        // and kept for the next push.
        let spare = &mut self.spare;
        let mut removed: usize = 0;
        self.fields.retain_mut(|field| {
            let value = match field {
                OutboundField::Raw {
                    tag: field_tag,
                    value,
                } if *field_tag == tag => value,
                OutboundField::Data {
                    length_tag,
                    data_tag,
                    value,
                } if *length_tag == tag || *data_tag == tag => value,
                OutboundField::Raw { .. } | OutboundField::Data { .. } => return true,
            };
            keep_spare(spare, std::mem::take(value));
            // A Vec holds fewer than `usize::MAX` fields, so the count of
            // those removed cannot overflow. Were it ever to, it stays at
            // the last value it reached rather than wrap.
            match removed.checked_add(1) {
                Some(next) => removed = next,
                None => debug_assert!(false, "removed more fields than a Vec can hold"),
            }
            false
        });
        removed
    }

    /// Returns the body fields in insertion order.
    #[must_use]
    pub fn fields(&self) -> &[OutboundField] {
        &self.fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outbound_message_fields_in_order() {
        let mut msg = OutboundMessage::new(MsgType::NewOrderSingle);
        msg.push_str(11, "ORDER-1")
            .push_char(54, '1')
            .push_uint(38, 100)
            .push_int(9999, -5)
            .push_bool(59, true);

        assert_eq!(msg.msg_type(), &MsgType::NewOrderSingle);
        let fields = msg.fields();
        assert_eq!(
            fields[0],
            OutboundField::Raw {
                tag: 11,
                value: b"ORDER-1".to_vec()
            }
        );
        assert_eq!(
            fields[1],
            OutboundField::Raw {
                tag: 54,
                value: b"1".to_vec()
            }
        );
        assert_eq!(
            fields[2],
            OutboundField::Raw {
                tag: 38,
                value: b"100".to_vec()
            }
        );
        assert_eq!(
            fields[3],
            OutboundField::Raw {
                tag: 9999,
                value: b"-5".to_vec()
            }
        );
        assert_eq!(
            fields[4],
            OutboundField::Raw {
                tag: 59,
                value: b"Y".to_vec()
            }
        );
    }

    #[test]
    fn test_outbound_message_push_data_records_a_counted_pair() {
        // A RawData payload carrying an embedded SOH is expressed as a
        // LENGTH/DATA pair, interleaved in insertion order with ordinary fields.
        let mut msg = OutboundMessage::new(MsgType::NewOrderSingle);
        msg.push_str(11, "ORDER-1")
            .push_data(95, 96, b"a\x01b".to_vec())
            .push_str(58, "after");

        let fields = msg.fields();
        assert_eq!(
            fields[1],
            OutboundField::Data {
                length_tag: 95,
                data_tag: 96,
                value: b"a\x01b".to_vec()
            }
        );
        // Insertion order is preserved across raw and data fields.
        assert_eq!(
            fields[0],
            OutboundField::Raw {
                tag: 11,
                value: b"ORDER-1".to_vec()
            }
        );
        assert_eq!(
            fields[2],
            OutboundField::Raw {
                tag: 58,
                value: b"after".to_vec()
            }
        );
    }

    #[test]
    fn test_outbound_message_get_and_remove_round_trip() {
        let mut msg = OutboundMessage::new(MsgType::Logon);
        msg.push_str(553, "trader").push_str(554, "secret");

        assert_eq!(msg.get(553), Some(&b"trader"[..]));
        assert_eq!(msg.get(9999), None);
        assert_eq!(msg.remove(554), 1);
        assert_eq!(msg.get(554), None);
        assert_eq!(msg.remove(554), 0);
        assert_eq!(msg.fields().len(), 1);
    }

    #[test]
    fn test_check_sendable_application_message_is_accepted() {
        let mut msg = OutboundMessage::new(MsgType::NewOrderSingle);
        msg.push_str(11, "ORDER-1").push_char(54, '1');
        assert!(check_sendable(&msg).is_ok());
    }

    #[test]
    fn test_check_sendable_admin_msg_type_is_reserved() {
        // Every administrative MsgType belongs to the session layer: one sent
        // behind the state machine's back leaves the engine's phase tracking
        // describing a session that no longer exists.
        for msg_type in [
            MsgType::Logon,
            MsgType::Logout,
            MsgType::SequenceReset,
            MsgType::Heartbeat,
            MsgType::TestRequest,
            MsgType::ResendRequest,
            MsgType::Reject,
        ] {
            let expected = msg_type.as_str().to_string();
            let msg = OutboundMessage::new(msg_type);
            match check_sendable(&msg) {
                Err(EngineError::ReservedMsgType { msg_type }) => assert_eq!(msg_type, expected),
                other => panic!("35={expected} must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_check_sendable_reserved_tag_is_refused() {
        for tag in RESERVED_TAGS {
            let mut msg = OutboundMessage::new(MsgType::NewOrderSingle);
            msg.push_str(tag, "1");
            match check_sendable(&msg) {
                Err(EngineError::ReservedTag { tag: actual }) => assert_eq!(actual, tag),
                other => panic!("tag {tag} must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_check_body_zero_tag_is_refused() {
        let mut msg = OutboundMessage::new(MsgType::NewOrderSingle);
        msg.push_str(0, "x");
        match check_body(&msg) {
            Err(EngineError::InvalidField { tag: 0, .. }) => {}
            other => panic!("tag 0 must be refused, got {other:?}"),
        }
    }

    #[test]
    fn test_check_body_empty_value_is_refused() {
        let mut msg = OutboundMessage::new(MsgType::NewOrderSingle);
        msg.push_str(11, "");
        match check_body(&msg) {
            Err(EngineError::InvalidField { tag: 11, .. }) => {}
            other => panic!("an empty value must be refused, got {other:?}"),
        }
    }

    #[test]
    fn test_check_body_soh_in_value_is_refused_without_quoting_it() {
        let mut msg = OutboundMessage::new(MsgType::NewOrderSingle);
        msg.push_str(58, "text\x0149=EVIL");
        match check_body(&msg) {
            Err(EngineError::InvalidField { tag: 58, reason }) => {
                assert!(
                    !reason.contains("EVIL"),
                    "the rejection must not quote the value, got {reason}"
                );
            }
            other => panic!("an embedded SOH must be refused, got {other:?}"),
        }
    }

    #[test]
    fn test_check_body_admin_missing_required_field_is_refused() {
        // The (MsgType, required-tag) pairs a `to_admin` callback must not be
        // able to strip and still have the message reach the wire.
        for (msg_type, required) in [
            (MsgType::Logon, 98u32),
            (MsgType::Logon, 108),
            (MsgType::TestRequest, 112),
            (MsgType::ResendRequest, 7),
            (MsgType::ResendRequest, 16),
            (MsgType::SequenceReset, 36),
        ] {
            let mut msg = OutboundMessage::new(msg_type.clone());
            // Populate every required tag, then drop just the one under test.
            for &tag in admin_required_tags(&msg_type) {
                msg.push_str(tag, "1");
            }
            assert_eq!(msg.remove(required), 1);
            match check_body(&msg) {
                Err(EngineError::MissingRequiredField {
                    msg_type: reported,
                    tag,
                }) => {
                    assert_eq!(reported, msg_type.as_str());
                    assert_eq!(tag, required);
                }
                other => {
                    panic!("{msg_type:?} without tag {required} must be refused, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn test_check_body_admin_with_all_required_fields_is_accepted() {
        let mut logon = OutboundMessage::new(MsgType::Logon);
        logon.push_uint(98, 0).push_uint(108, 30);
        assert!(check_body(&logon).is_ok());
    }

    #[test]
    fn test_check_body_application_message_has_no_required_admin_fields() {
        // An application MsgType places no admin-required-field demand, so an
        // empty body is fine here (per-field checks aside).
        let msg = OutboundMessage::new(MsgType::NewOrderSingle);
        assert!(check_body(&msg).is_ok());
    }

    #[test]
    fn test_outbound_message_debug_redacts_credentials() {
        let mut msg = OutboundMessage::new(MsgType::Logon);
        msg.push_str(553, "trader")
            .push_str(554, "s3cret-password")
            .push_str(925, "n3w-password")
            .push_str(96, "raw-secret-bytes");
        let rendered = format!("{msg:?}");

        // The username is not a credential and stays visible.
        assert!(rendered.contains("trader"), "got {rendered}");
        // None of the credential values may appear.
        for secret in ["s3cret-password", "n3w-password", "raw-secret-bytes"] {
            assert!(
                !rendered.contains(secret),
                "Debug must not print {secret}, got {rendered}"
            );
        }
        assert!(rendered.contains("<redacted>"), "got {rendered}");
    }

    /// The address of a field's value buffer, to see it reused.
    fn value_ptr(message: &OutboundMessage, index: usize) -> *const u8 {
        match message.fields().get(index) {
            Some(OutboundField::Raw { value, .. } | OutboundField::Data { value, .. }) => {
                value.as_ptr()
            }
            None => panic!("no field {index}"),
        }
    }

    #[test]
    fn test_pool_reuses_the_storage_of_a_dropped_message() {
        let pool = OutboundPool::new(4);
        let mut first = pool.acquire(MsgType::NewOrderSingle);
        assert!(first.is_pooled());
        first.push_str(11, "ORDER-1").push_uint(38, 100);
        let fields_ptr = first.fields().as_ptr();
        let value_ptrs = [value_ptr(&first, 0), value_ptr(&first, 1)];
        drop(first);
        assert_eq!(pool.idle(), 1, "the dropped message went back to the pool");

        let mut second = pool.acquire(MsgType::OrderCancelRequest);
        assert_eq!(pool.idle(), 0);
        second.push_str(41, "ORDER-1").push_char(54, '2');
        assert_eq!(
            second.fields().as_ptr(),
            fields_ptr,
            "the field list is reused"
        );
        // Each position gets its own buffer back.
        assert_eq!(value_ptr(&second, 0), value_ptrs[0]);
        assert_eq!(value_ptr(&second, 1), value_ptrs[1]);
    }

    #[test]
    fn test_pool_reuse_leaves_no_stale_field() {
        let pool = OutboundPool::new(1);
        let mut first = pool.acquire(MsgType::NewOrderSingle);
        first
            .push_str(11, "A-LONG-CLIENT-ORDER-ID")
            .push_str(55, "EUR/USD")
            .push_int(9999, -42)
            .push_data(95, 96, b"x\x01y".to_vec())
            .push_bool(59, true);
        drop(first);

        let mut second = pool.acquire(MsgType::OrderCancelRequest);
        assert_eq!(second.msg_type(), &MsgType::OrderCancelRequest);
        assert!(second.fields().is_empty(), "no field survives the reuse");
        second
            .push_str(11, "B")
            .push_int(9999, 7)
            .push_bool(59, false);
        assert_eq!(
            second.fields(),
            [
                OutboundField::Raw {
                    tag: 11,
                    value: b"B".to_vec()
                },
                OutboundField::Raw {
                    tag: 9999,
                    value: b"7".to_vec()
                },
                OutboundField::Raw {
                    tag: 59,
                    value: b"N".to_vec()
                },
            ]
        );
        for tag in [55, 95, 96] {
            assert_eq!(second.get(tag), None, "tag {tag} is stale");
        }
        assert!(check_sendable(&second).is_ok());
    }

    #[test]
    fn test_pool_exhaustion_builds_fresh_messages_and_stays_bounded() {
        let pool = OutboundPool::new(2);
        // More messages held at once than the pool keeps: acquire never
        // blocks nor fails, it builds what the pool does not have.
        let held: Vec<OutboundMessage> = (0..5)
            .map(|_| pool.acquire(MsgType::NewOrderSingle))
            .collect();
        assert!(held.iter().all(OutboundMessage::is_pooled));
        assert_eq!(pool.idle(), 0);
        drop(held);
        assert_eq!(pool.idle(), 2, "a full pool frees what comes back");
        let _a = pool.acquire(MsgType::NewOrderSingle);
        let _b = pool.acquire(MsgType::NewOrderSingle);
        let _c = pool.acquire(MsgType::NewOrderSingle);
        assert_eq!(pool.idle(), 0);
    }

    #[test]
    fn test_pool_takes_back_a_message_dropped_unsent() {
        let pool = OutboundPool::new(8);
        {
            let mut message = pool.acquire(MsgType::NewOrderSingle);
            message.push_str(11, "never-sent");
        }
        assert_eq!(pool.idle(), 1, "a message dropped unsent does not leak");
        // A held message does not stop the others from being taken.
        let held = pool.acquire(MsgType::NewOrderSingle);
        let other = pool.acquire(MsgType::NewOrderSingle);
        assert!(held.is_pooled() && other.is_pooled());
        drop(other);
        assert_eq!(pool.idle(), 1);
        drop(held);
        assert_eq!(pool.idle(), 2);
    }

    #[test]
    fn test_pool_frees_an_oversized_message_instead_of_keeping_it() {
        let pool = OutboundPool::new(4);
        let mut message = pool.acquire(MsgType::NewOrderSingle);
        for tag in 1..=u32::try_from(POOLED_MAX_FIELDS + 1).unwrap_or(u32::MAX) {
            message.push_str(1000 + tag, "v");
        }
        drop(message);
        assert_eq!(pool.idle(), 0, "an oversized field list is not pooled");

        let mut message = pool.acquire(MsgType::NewOrderSingle);
        message.push_raw(58, vec![b'x'; POOLED_MAX_VALUE_BYTES * 2]);
        message.push_str(11, "small");
        drop(message);
        let message = pool.acquire(MsgType::NewOrderSingle);
        assert_eq!(message.spare.len(), 1, "only the small buffer was kept");
    }

    #[test]
    fn test_clone_of_a_pooled_message_is_not_pooled() {
        let pool = OutboundPool::new(4);
        let mut message = pool.acquire(MsgType::NewOrderSingle);
        message.push_str(11, "ORDER-1");
        let copy = message.clone();
        assert!(!copy.is_pooled());
        assert_eq!(copy.get(11), Some(&b"ORDER-1"[..]));
        drop(copy);
        assert_eq!(pool.idle(), 0);
        drop(message);
        assert_eq!(pool.idle(), 1);
    }

    #[test]
    fn test_remove_keeps_the_buffer_for_the_next_push() {
        let mut message = OutboundMessage::new(MsgType::NewOrderSingle);
        message.push_str(58, "first");
        let ptr = value_ptr(&message, 0);
        assert_eq!(message.remove(58), 1);
        message.push_str(58, "again");
        assert_eq!(value_ptr(&message, 0), ptr);
        assert_eq!(message.get(58), Some(&b"again"[..]));
    }

    #[test]
    fn test_pool_alternating_value_sizes_reach_a_steady_state() {
        // A buffer grown by doubling from 600 to 1200 bytes would pass the
        // 1024-byte cap for a 1000-byte value and be freed on every cycle.
        let pool = OutboundPool::new(1);
        let small = vec![b's'; 600];
        let large = vec![b'l'; 1000];
        let mut steady = None;
        for cycle in 0..200 {
            let value = if cycle % 2 == 0 { &small } else { &large };
            let mut message = pool.acquire(MsgType::NewOrderSingle);
            message.push_bytes(58, value);
            assert_eq!(message.get(58), Some(value.as_slice()));
            let ptr = value_ptr(&message, 0);
            drop(message);
            assert_eq!(pool.idle(), 1);
            let kept = pool.acquire(MsgType::NewOrderSingle);
            assert_eq!(kept.spare.len(), 1, "cycle {cycle}: the buffer was freed");
            drop(kept);
            if cycle >= 2 {
                // Once a 1000-byte value has been seen, the same buffer serves
                // every cycle: no allocation.
                assert_eq!(*steady.get_or_insert(ptr), ptr, "cycle {cycle} reallocated");
            }
        }
    }

    #[test]
    fn test_remove_many_matches_keeps_order_and_buffers() {
        let mut message = OutboundMessage::new(MsgType::NewOrderSingle);
        for index in 0..10_000_u64 {
            if index % 2 == 0 {
                message.push_str(58, "drop");
            } else {
                message.push_uint(9000, index);
            }
        }
        message.push_data(95, 96, b"a\x01b".to_vec());
        assert_eq!(message.remove(58), 5_000);
        assert_eq!(message.fields().len(), 5_001);
        for (position, field) in message.fields().iter().take(5_000).enumerate() {
            let expected = (2 * position + 1).to_string();
            assert_eq!(
                field,
                &OutboundField::Raw {
                    tag: 9000,
                    value: expected.into_bytes()
                }
            );
        }
        assert_eq!(
            message.spare.len(),
            POOLED_MAX_SPARE,
            "removed buffers are kept, bounded"
        );
        // Either half of a counted pair removes the pair.
        assert_eq!(message.remove(95), 1);
        assert_eq!(message.get(96), None);
        assert_eq!(message.remove(58), 0);
    }

    #[test]
    fn test_push_int_and_uint_extremes() {
        let mut message = OutboundMessage::new(MsgType::NewOrderSingle);
        message
            .push_int(1, i64::MIN)
            .push_int(2, 0)
            .push_uint(3, u64::MAX);
        assert_eq!(message.get(1), Some(i64::MIN.to_string().as_bytes()));
        assert_eq!(message.get(2), Some(&b"0"[..]));
        assert_eq!(message.get(3), Some(u64::MAX.to_string().as_bytes()));
    }
}
