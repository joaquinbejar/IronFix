/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Message types and traits for FIX protocol.
//!
//! This module provides:
//! - [`RawMessage`]: Zero-copy view into a FIX message buffer
//! - [`OwnedMessage`]: Owned message for storage and cross-thread transfer
//! - [`MsgType`]: Enumeration of FIX message types
//! - [`FixMessage`]: Trait for typed message access

use crate::error::DecodeError;
use crate::field::FieldRef;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::fmt;
use std::ops::Range;

/// Standard FIX message types.
///
/// This enum covers the most common administrative and application messages.
/// Custom or less common message types can be represented as `Custom(String)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum MsgType {
    /// Heartbeat (0) - Session level.
    #[default]
    Heartbeat,
    /// Test Request (1) - Session level.
    TestRequest,
    /// Resend Request (2) - Session level.
    ResendRequest,
    /// Reject (3) - Session level.
    Reject,
    /// Sequence Reset (4) - Session level.
    SequenceReset,
    /// Logout (5) - Session level.
    Logout,
    /// Indication of Interest (6).
    IndicationOfInterest,
    /// Advertisement (7).
    Advertisement,
    /// Execution Report (8).
    ExecutionReport,
    /// Order Cancel Reject (9).
    OrderCancelReject,
    /// Logon (A) - Session level.
    Logon,
    /// News (B).
    News,
    /// Email (C).
    Email,
    /// New Order Single (D).
    NewOrderSingle,
    /// New Order List (E).
    NewOrderList,
    /// Order Cancel Request (F).
    OrderCancelRequest,
    /// Order Cancel/Replace Request (G).
    OrderCancelReplaceRequest,
    /// Order Status Request (H).
    OrderStatusRequest,
    /// Allocation Instruction (J).
    AllocationInstruction,
    /// List Cancel Request (K).
    ListCancelRequest,
    /// List Execute (L).
    ListExecute,
    /// List Status Request (M).
    ListStatusRequest,
    /// List Status (N).
    ListStatus,
    /// Allocation Instruction Ack (P).
    AllocationInstructionAck,
    /// Don't Know Trade (Q).
    DontKnowTrade,
    /// Quote Request (R).
    QuoteRequest,
    /// Quote (S).
    Quote,
    /// Settlement Instructions (T).
    SettlementInstructions,
    /// Market Data Request (V).
    MarketDataRequest,
    /// Market Data Snapshot/Full Refresh (W).
    MarketDataSnapshotFullRefresh,
    /// Market Data Incremental Refresh (X).
    MarketDataIncrementalRefresh,
    /// Market Data Request Reject (Y).
    MarketDataRequestReject,
    /// Quote Cancel (Z).
    QuoteCancel,
    /// Quote Status Request (a).
    QuoteStatusRequest,
    /// Mass Quote Acknowledgement (b).
    MassQuoteAcknowledgement,
    /// Security Definition Request (c).
    SecurityDefinitionRequest,
    /// Security Definition (d).
    SecurityDefinition,
    /// Security Status Request (e).
    SecurityStatusRequest,
    /// Security Status (f).
    SecurityStatus,
    /// Trading Session Status Request (g).
    TradingSessionStatusRequest,
    /// Trading Session Status (h).
    TradingSessionStatus,
    /// Mass Quote (i).
    MassQuote,
    /// Business Message Reject (j).
    BusinessMessageReject,
    /// Bid Request (k).
    BidRequest,
    /// Bid Response (l).
    BidResponse,
    /// List Strike Price (m).
    ListStrikePrice,
    /// XML Message (n).
    XmlMessage,
    /// Registration Instructions (o).
    RegistrationInstructions,
    /// Registration Instructions Response (p).
    RegistrationInstructionsResponse,
    /// Order Mass Cancel Request (q).
    OrderMassCancelRequest,
    /// Order Mass Cancel Report (r).
    OrderMassCancelReport,
    /// New Order Cross (s).
    NewOrderCross,
    /// Cross Order Cancel/Replace Request (t).
    CrossOrderCancelReplaceRequest,
    /// Cross Order Cancel Request (u).
    CrossOrderCancelRequest,
    /// Security Type Request (v).
    SecurityTypeRequest,
    /// Security Types (w).
    SecurityTypes,
    /// Security List Request (x).
    SecurityListRequest,
    /// Security List (y).
    SecurityList,
    /// Derivative Security List Request (z).
    DerivativeSecurityListRequest,
    /// Custom or unknown message type.
    Custom(String),
}

impl std::str::FromStr for MsgType {
    type Err = std::convert::Infallible;

    /// Creates a MsgType from a string value.
    ///
    /// # Arguments
    /// * `s` - The message type string (e.g., "D" for NewOrderSingle)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "0" => Self::Heartbeat,
            "1" => Self::TestRequest,
            "2" => Self::ResendRequest,
            "3" => Self::Reject,
            "4" => Self::SequenceReset,
            "5" => Self::Logout,
            "6" => Self::IndicationOfInterest,
            "7" => Self::Advertisement,
            "8" => Self::ExecutionReport,
            "9" => Self::OrderCancelReject,
            "A" => Self::Logon,
            "B" => Self::News,
            "C" => Self::Email,
            "D" => Self::NewOrderSingle,
            "E" => Self::NewOrderList,
            "F" => Self::OrderCancelRequest,
            "G" => Self::OrderCancelReplaceRequest,
            "H" => Self::OrderStatusRequest,
            "J" => Self::AllocationInstruction,
            "K" => Self::ListCancelRequest,
            "L" => Self::ListExecute,
            "M" => Self::ListStatusRequest,
            "N" => Self::ListStatus,
            "P" => Self::AllocationInstructionAck,
            "Q" => Self::DontKnowTrade,
            "R" => Self::QuoteRequest,
            "S" => Self::Quote,
            "T" => Self::SettlementInstructions,
            "V" => Self::MarketDataRequest,
            "W" => Self::MarketDataSnapshotFullRefresh,
            "X" => Self::MarketDataIncrementalRefresh,
            "Y" => Self::MarketDataRequestReject,
            "Z" => Self::QuoteCancel,
            "a" => Self::QuoteStatusRequest,
            "b" => Self::MassQuoteAcknowledgement,
            "c" => Self::SecurityDefinitionRequest,
            "d" => Self::SecurityDefinition,
            "e" => Self::SecurityStatusRequest,
            "f" => Self::SecurityStatus,
            "g" => Self::TradingSessionStatusRequest,
            "h" => Self::TradingSessionStatus,
            "i" => Self::MassQuote,
            "j" => Self::BusinessMessageReject,
            "k" => Self::BidRequest,
            "l" => Self::BidResponse,
            "m" => Self::ListStrikePrice,
            "n" => Self::XmlMessage,
            "o" => Self::RegistrationInstructions,
            "p" => Self::RegistrationInstructionsResponse,
            "q" => Self::OrderMassCancelRequest,
            "r" => Self::OrderMassCancelReport,
            "s" => Self::NewOrderCross,
            "t" => Self::CrossOrderCancelReplaceRequest,
            "u" => Self::CrossOrderCancelRequest,
            "v" => Self::SecurityTypeRequest,
            "w" => Self::SecurityTypes,
            "x" => Self::SecurityListRequest,
            "y" => Self::SecurityList,
            "z" => Self::DerivativeSecurityListRequest,
            other => Self::Custom(other.to_string()),
        })
    }
}

impl MsgType {
    /// Returns the string representation of this message type.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Heartbeat => "0",
            Self::TestRequest => "1",
            Self::ResendRequest => "2",
            Self::Reject => "3",
            Self::SequenceReset => "4",
            Self::Logout => "5",
            Self::IndicationOfInterest => "6",
            Self::Advertisement => "7",
            Self::ExecutionReport => "8",
            Self::OrderCancelReject => "9",
            Self::Logon => "A",
            Self::News => "B",
            Self::Email => "C",
            Self::NewOrderSingle => "D",
            Self::NewOrderList => "E",
            Self::OrderCancelRequest => "F",
            Self::OrderCancelReplaceRequest => "G",
            Self::OrderStatusRequest => "H",
            Self::AllocationInstruction => "J",
            Self::ListCancelRequest => "K",
            Self::ListExecute => "L",
            Self::ListStatusRequest => "M",
            Self::ListStatus => "N",
            Self::AllocationInstructionAck => "P",
            Self::DontKnowTrade => "Q",
            Self::QuoteRequest => "R",
            Self::Quote => "S",
            Self::SettlementInstructions => "T",
            Self::MarketDataRequest => "V",
            Self::MarketDataSnapshotFullRefresh => "W",
            Self::MarketDataIncrementalRefresh => "X",
            Self::MarketDataRequestReject => "Y",
            Self::QuoteCancel => "Z",
            Self::QuoteStatusRequest => "a",
            Self::MassQuoteAcknowledgement => "b",
            Self::SecurityDefinitionRequest => "c",
            Self::SecurityDefinition => "d",
            Self::SecurityStatusRequest => "e",
            Self::SecurityStatus => "f",
            Self::TradingSessionStatusRequest => "g",
            Self::TradingSessionStatus => "h",
            Self::MassQuote => "i",
            Self::BusinessMessageReject => "j",
            Self::BidRequest => "k",
            Self::BidResponse => "l",
            Self::ListStrikePrice => "m",
            Self::XmlMessage => "n",
            Self::RegistrationInstructions => "o",
            Self::RegistrationInstructionsResponse => "p",
            Self::OrderMassCancelRequest => "q",
            Self::OrderMassCancelReport => "r",
            Self::NewOrderCross => "s",
            Self::CrossOrderCancelReplaceRequest => "t",
            Self::CrossOrderCancelRequest => "u",
            Self::SecurityTypeRequest => "v",
            Self::SecurityTypes => "w",
            Self::SecurityListRequest => "x",
            Self::SecurityList => "y",
            Self::DerivativeSecurityListRequest => "z",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Returns true if this is an administrative message.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        matches!(
            self,
            Self::Heartbeat
                | Self::TestRequest
                | Self::ResendRequest
                | Self::Reject
                | Self::SequenceReset
                | Self::Logout
                | Self::Logon
        )
    }

    /// Returns true if this is an application message.
    #[must_use]
    pub fn is_app(&self) -> bool {
        !self.is_admin()
    }
}

impl fmt::Display for MsgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Zero-copy view into a FIX message buffer.
///
/// This struct holds references to the original message buffer,
/// avoiding allocation during parsing. Fields are stored as
/// offset ranges into the buffer.
///
/// # Range convention
///
/// **Every stored range is relative to `buffer`, not to whatever larger buffer
/// the message may have been decoded from.** A decoder that reads several
/// messages out of one input must rebase its offsets by the start of the
/// current message before constructing a `RawMessage`; [`RawMessage::new`]
/// rejects any range that does not lie within `buffer`.
#[derive(Debug, Clone)]
pub struct RawMessage<'a> {
    /// The complete message buffer.
    buffer: &'a [u8],
    /// Range of the BeginString field value, relative to `buffer`.
    begin_string: Range<usize>,
    /// Range of the message body (after BodyLength, before checksum),
    /// relative to `buffer`.
    body: Range<usize>,
    /// The parsed message type.
    msg_type: MsgType,
    /// Parsed field references (tag and value ranges).
    fields: SmallVec<[FieldRef<'a>; 32]>,
}

/// Validates that `range` is well ordered and lies within `buffer_len` bytes.
#[inline]
fn check_range(range: &Range<usize>, buffer_len: usize) -> Result<(), DecodeError> {
    if range.start > range.end || range.end > buffer_len {
        return Err(DecodeError::RangeOutOfBounds {
            start: range.start,
            end: range.end,
            buffer_len,
        });
    }
    Ok(())
}

impl<'a> RawMessage<'a> {
    /// Creates a new RawMessage from parsed components.
    ///
    /// # Arguments
    /// * `buffer` - The complete message buffer
    /// * `begin_string` - Range of the BeginString value, relative to `buffer`
    /// * `body` - Range of the message body, relative to `buffer`
    /// * `msg_type` - The parsed message type
    /// * `fields` - Parsed field references
    ///
    /// # Errors
    /// Returns [`DecodeError::RangeOutOfBounds`] if `begin_string` or `body`
    /// is inverted or does not lie within `buffer`. Every offset here derives
    /// from attacker-supplied bytes, so the bounds are checked once at
    /// construction rather than at every accessor.
    pub fn new(
        buffer: &'a [u8],
        begin_string: Range<usize>,
        body: Range<usize>,
        msg_type: MsgType,
        fields: SmallVec<[FieldRef<'a>; 32]>,
    ) -> Result<Self, DecodeError> {
        check_range(&begin_string, buffer.len())?;
        check_range(&body, buffer.len())?;

        Ok(Self {
            buffer,
            begin_string,
            body,
            msg_type,
            fields,
        })
    }

    /// Returns the complete message buffer.
    #[inline]
    #[must_use]
    pub const fn buffer(&self) -> &'a [u8] {
        self.buffer
    }

    /// Returns the BeginString value (e.g., "FIX.4.4").
    ///
    /// # Errors
    /// Returns [`DecodeError::InvalidUtf8`] if the BeginString bytes are not
    /// valid UTF-8, or [`DecodeError::RangeOutOfBounds`] if the stored range
    /// escapes the buffer. The value is never silently defaulted to `""`.
    pub fn begin_string(&self) -> Result<&'a str, DecodeError> {
        let range = self.begin_string.clone();
        debug_assert!(
            range.end <= self.buffer.len(),
            "RawMessage ranges must be buffer-relative"
        );
        let bytes = self
            .buffer
            .get(range.clone())
            .ok_or(DecodeError::RangeOutOfBounds {
                start: range.start,
                end: range.end,
                buffer_len: self.buffer.len(),
            })?;
        std::str::from_utf8(bytes).map_err(DecodeError::from)
    }

    /// Returns the message body bytes (after BodyLength, before the checksum).
    ///
    /// # Errors
    /// Returns [`DecodeError::RangeOutOfBounds`] if the stored range escapes
    /// the buffer.
    pub fn body(&self) -> Result<&'a [u8], DecodeError> {
        let range = self.body.clone();
        debug_assert!(
            range.end <= self.buffer.len(),
            "RawMessage ranges must be buffer-relative"
        );
        self.buffer
            .get(range.clone())
            .ok_or(DecodeError::RangeOutOfBounds {
                start: range.start,
                end: range.end,
                buffer_len: self.buffer.len(),
            })
    }

    /// Returns the message type.
    #[inline]
    #[must_use]
    pub fn msg_type(&self) -> &MsgType {
        &self.msg_type
    }

    /// Returns an iterator over all fields.
    #[inline]
    pub fn fields(&self) -> impl Iterator<Item = &FieldRef<'a>> {
        self.fields.iter()
    }

    /// Returns the number of fields in the message.
    #[inline]
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Gets a field by tag number.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    ///
    /// # Returns
    /// The first field with the given tag, or `None` if not found.
    #[must_use]
    pub fn get_field(&self, tag: u32) -> Option<&FieldRef<'a>> {
        self.fields.iter().find(|f| f.tag == tag)
    }

    /// Gets a field value as a string.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    ///
    /// # Returns
    /// The field value as a string, or `None` if not found or invalid UTF-8.
    #[must_use]
    pub fn get_field_str(&self, tag: u32) -> Option<&'a str> {
        self.get_field(tag).and_then(|f| f.as_str().ok())
    }

    /// Gets a field value parsed as the specified type.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    ///
    /// # Errors
    /// Returns `DecodeError` if the field is not found or cannot be parsed.
    pub fn get_field_as<T: std::str::FromStr>(&self, tag: u32) -> Result<T, DecodeError> {
        self.get_field(tag)
            .ok_or(DecodeError::MissingRequiredField { tag })?
            .parse()
    }

    /// Returns the message body range.
    #[inline]
    #[must_use]
    pub fn body_range(&self) -> &Range<usize> {
        &self.body
    }

    /// Returns the message length in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns true if the message is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Converts this borrowed message to an owned message.
    #[must_use]
    pub fn to_owned(&self) -> OwnedMessage {
        OwnedMessage::from_raw(self)
    }
}

/// Owned FIX message for storage and cross-thread transfer.
///
/// Unlike [`RawMessage`], this struct owns its data and can be
/// safely sent across threads or stored for later use.
#[derive(Debug, Clone)]
pub struct OwnedMessage {
    /// The complete message buffer.
    buffer: Bytes,
    /// The parsed message type.
    msg_type: MsgType,
    /// Field offsets: (tag, value_range).
    field_offsets: Vec<(u32, Range<usize>)>,
}

impl OwnedMessage {
    /// Creates an OwnedMessage from a RawMessage.
    ///
    /// # Arguments
    /// * `raw` - The raw message to copy
    #[must_use]
    pub fn from_raw(raw: &RawMessage<'_>) -> Self {
        let buffer = Bytes::copy_from_slice(raw.buffer);
        let field_offsets = raw
            .fields
            .iter()
            .map(|f| {
                let start = f.value.as_ptr() as usize - raw.buffer.as_ptr() as usize;
                let end = start + f.value.len();
                (f.tag, start..end)
            })
            .collect();

        Self {
            buffer,
            msg_type: raw.msg_type.clone(),
            field_offsets,
        }
    }

    /// Creates an OwnedMessage from raw bytes.
    ///
    /// # Arguments
    /// * `buffer` - The message bytes
    /// * `msg_type` - The message type
    /// * `field_offsets` - Field tag and value range pairs
    #[must_use]
    pub fn new(buffer: Bytes, msg_type: MsgType, field_offsets: Vec<(u32, Range<usize>)>) -> Self {
        Self {
            buffer,
            msg_type,
            field_offsets,
        }
    }

    /// Returns the message type.
    #[inline]
    #[must_use]
    pub fn msg_type(&self) -> &MsgType {
        &self.msg_type
    }

    /// Returns the message bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Returns the message length in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns true if the message is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Gets a field value by tag.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    ///
    /// # Returns
    /// The field value bytes, or `None` if not found or if the stored offset
    /// escapes the buffer.
    #[must_use]
    pub fn get_field(&self, tag: u32) -> Option<&[u8]> {
        self.field_offsets
            .iter()
            .find(|(t, _)| *t == tag)
            .and_then(|(_, range)| self.buffer.get(range.clone()))
    }

    /// Gets a field value as a string.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    ///
    /// # Returns
    /// The field value as a string, or `None` if not found or invalid UTF-8.
    #[must_use]
    pub fn get_field_str(&self, tag: u32) -> Option<&str> {
        self.get_field(tag)
            .and_then(|b| std::str::from_utf8(b).ok())
    }

    /// Returns the number of fields.
    #[inline]
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.field_offsets.len()
    }

    /// Consumes the message and returns the underlying buffer.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.buffer
    }
}

/// Trait for typed FIX message access.
///
/// This trait is implemented by generated message types to provide
/// type-safe encoding and decoding.
pub trait FixMessage: Sized {
    /// The message type string (e.g., "D" for NewOrderSingle).
    const MSG_TYPE: &'static str;

    /// Decodes a message from a raw message.
    ///
    /// # Arguments
    /// * `raw` - The raw message to decode
    ///
    /// # Errors
    /// Returns `DecodeError` if the message cannot be decoded.
    fn from_raw(raw: &RawMessage<'_>) -> Result<Self, DecodeError>;

    /// Encodes the message to a buffer.
    ///
    /// # Arguments
    /// * `buf` - The buffer to write to
    ///
    /// # Errors
    /// Returns `EncodeError` if the message cannot be encoded.
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), crate::error::EncodeError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msg_type_from_str() {
        assert_eq!("0".parse::<MsgType>(), Ok(MsgType::Heartbeat));
        assert_eq!("A".parse::<MsgType>(), Ok(MsgType::Logon));
        assert_eq!("D".parse::<MsgType>(), Ok(MsgType::NewOrderSingle));
        assert_eq!("8".parse::<MsgType>(), Ok(MsgType::ExecutionReport));
    }

    #[test]
    fn test_msg_type_as_str() {
        assert_eq!(MsgType::Heartbeat.as_str(), "0");
        assert_eq!(MsgType::Logon.as_str(), "A");
        assert_eq!(MsgType::NewOrderSingle.as_str(), "D");
    }

    #[test]
    fn test_msg_type_is_admin() {
        assert!(MsgType::Heartbeat.is_admin());
        assert!(MsgType::Logon.is_admin());
        assert!(MsgType::Logout.is_admin());
        assert!(!MsgType::NewOrderSingle.is_admin());
        assert!(!MsgType::ExecutionReport.is_admin());
    }

    #[test]
    fn test_msg_type_custom() {
        let custom = MsgType::Custom("XX".to_string());
        assert_eq!("XX".parse::<MsgType>(), Ok(custom.clone()));
        assert_eq!(custom.as_str(), "XX");
    }

    /// Builds the field list for a one-field `RawMessage` over `buffer`.
    fn single_field(buffer: &[u8]) -> SmallVec<[FieldRef<'_>; 32]> {
        let mut fields = SmallVec::new();
        fields.push(FieldRef::new(8, buffer));
        fields
    }

    #[test]
    fn test_raw_message_new_rejects_begin_string_range_past_buffer() {
        let buffer: &[u8] = b"8=FIX.4.4\x01";
        let fields = single_field(buffer);
        let result = RawMessage::new(buffer, 2..64, 0..0, MsgType::Heartbeat, fields);
        assert_eq!(
            result.err(),
            Some(DecodeError::RangeOutOfBounds {
                start: 2,
                end: 64,
                buffer_len: buffer.len(),
            })
        );
    }

    #[test]
    fn test_raw_message_new_rejects_body_range_past_buffer() {
        let buffer: &[u8] = b"8=FIX.4.4\x01";
        let fields = single_field(buffer);
        let result = RawMessage::new(buffer, 2..9, 0..11, MsgType::Heartbeat, fields);
        assert!(matches!(
            result.err(),
            Some(DecodeError::RangeOutOfBounds { .. })
        ));
    }

    #[test]
    fn test_raw_message_new_rejects_inverted_range() {
        let buffer: &[u8] = b"8=FIX.4.4\x01";
        let fields = single_field(buffer);
        // Built via the struct literal: `9..2` as a literal range trips
        // `clippy::reversed_empty_ranges` before it can reach the check.
        let inverted = Range { start: 9, end: 2 };
        let result = RawMessage::new(buffer, inverted, 0..0, MsgType::Heartbeat, fields);
        assert!(matches!(
            result.err(),
            Some(DecodeError::RangeOutOfBounds { .. })
        ));
    }

    #[test]
    fn test_raw_message_begin_string_and_body_are_buffer_relative() {
        let buffer: &[u8] = b"8=FIX.4.4\x0135=0\x01";
        let fields = single_field(buffer);
        let Ok(msg) = RawMessage::new(buffer, 2..9, 10..15, MsgType::Heartbeat, fields) else {
            panic!("in-bounds ranges must be accepted");
        };
        assert_eq!(msg.begin_string(), Ok("FIX.4.4"));
        assert_eq!(msg.body(), Ok(&b"35=0\x01"[..]));
        assert_eq!(msg.len(), buffer.len());
    }

    #[test]
    fn test_raw_message_begin_string_invalid_utf8_is_typed_error() {
        let buffer: &[u8] = b"8=\xff\xfe\x01";
        let fields = single_field(buffer);
        let Ok(msg) = RawMessage::new(buffer, 2..4, 0..0, MsgType::Heartbeat, fields) else {
            panic!("in-bounds ranges must be accepted");
        };
        assert!(matches!(
            msg.begin_string(),
            Err(DecodeError::InvalidUtf8(_))
        ));
    }

    #[test]
    fn test_owned_message_get_field_out_of_bounds_offset_returns_none() {
        let buffer = Bytes::from_static(b"8=FIX.4.4\x01");
        let msg = OwnedMessage::new(buffer, MsgType::Heartbeat, vec![(8, 2..64)]);
        assert_eq!(msg.get_field(8), None);
    }

    #[test]
    fn test_owned_message_field_access() {
        // Buffer: "8=FIX.4.4\x0135=D\x0149=SENDER\x01"
        // Offsets: 8=FIX.4.4 (0-9), \x01 (9), 35=D (10-13), \x01 (14), 49=SENDER (15-23), \x01 (24)
        // FIX.4.4 is at 2..9, D is at 13..14, SENDER is at 18..24
        let buffer = Bytes::from_static(b"8=FIX.4.4\x0135=D\x0149=SENDER\x01");
        let field_offsets = vec![(8, 2..9), (35, 13..14), (49, 18..24)];
        let msg = OwnedMessage::new(buffer, MsgType::NewOrderSingle, field_offsets);

        assert_eq!(msg.get_field_str(8), Some("FIX.4.4"));
        assert_eq!(msg.get_field_str(35), Some("D"));
        assert_eq!(msg.get_field_str(49), Some("SENDER"));
        assert_eq!(msg.get_field_str(999), None);
    }
}
