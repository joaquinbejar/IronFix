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

/// Declares [`MsgType`] and the three mappings that must agree about it.
///
/// The variant, its wire code, and its admin/app category are stated **once**
/// per row; `as_str`, the `from_str` reverse lookup, and `is_admin` are all
/// generated from that single table, so the three cannot drift. A row's
/// category must match the `msgcat` the dictionary gives that MsgType — see
/// [`MsgType::is_admin`].
macro_rules! define_msg_types {
    (
        $(
            $(#[$variant_meta:meta])*
            $variant:ident = $code:literal, admin = $admin:literal;
        )*
    ) => {
        /// Standard FIX message types.
        ///
        /// This enum covers the most common administrative and application
        /// messages. Custom or less common message types are represented as
        /// `Custom(String)`.
        ///
        /// # Equality follows the wire form
        ///
        /// [`PartialEq`] and [`Hash`] compare [`MsgType::as_str`], not the
        /// variant: `MsgType::Custom("D".into()) == MsgType::NewOrderSingle`,
        /// because both put `35=D` on the wire. Without that, a `Custom` value
        /// reaching a `HashMap` keyed by `MsgType` would silently miss the
        /// entry its own wire form should have hit. Prefer [`MsgType::new`],
        /// which folds a known code into its named variant.
        #[derive(Debug, Clone, Serialize, Deserialize, Default)]
        pub enum MsgType {
            $(
                $(#[$variant_meta])*
                $variant,
            )*
            /// Custom or unknown message type.
            Custom(String),
        }

        impl MsgType {
            /// Returns the string representation of this message type.
            #[must_use]
            pub fn as_str(&self) -> &str {
                match self {
                    $( Self::$variant => $code, )*
                    Self::Custom(s) => s.as_str(),
                }
            }

            /// Creates a MsgType from its on-the-wire code.
            ///
            /// A code this enum names folds into that named variant, so the
            /// result is always in normal form; anything else becomes
            /// [`MsgType::Custom`].
            ///
            /// # Arguments
            /// * `code` - The message type string (e.g., "D" for NewOrderSingle)
            #[must_use]
            pub fn new(code: &str) -> Self {
                match code {
                    $( $code => Self::$variant, )*
                    other => Self::Custom(other.to_owned()),
                }
            }

            /// Returns true if this is an administrative (session-level)
            /// message.
            ///
            /// The classification is the `msgcat` attribute the FIX dictionary
            /// gives each MsgType, and this list must agree with it. Note that
            /// XMLnonFIX (`n`) is `msgcat='admin'` in `FIX44.xml`, so it is
            /// administrative despite not being one of the seven classic
            /// session messages.
            ///
            /// A [`MsgType::Custom`] carrying a code this table names is
            /// classified by that code, so two values that compare equal
            /// always agree here. A genuinely unrecognised code is treated as
            /// an application message: nothing here knows a private code's
            /// category, and routing an unknown message through the session
            /// path would let a counterparty reach session handling with a
            /// type this engine cannot interpret.
            #[must_use]
            pub fn is_admin(&self) -> bool {
                match self {
                    $( Self::$variant => $admin, )*
                    // Same table, reached by wire code rather than by
                    // discriminant; borrows the code, never allocates.
                    Self::Custom(code) => match code.as_str() {
                        $( $code => $admin, )*
                        _ => false,
                    },
                }
            }
        }

        #[cfg(test)]
        impl MsgType {
            /// Every named variant, for exhaustive round-trip tests.
            fn all_named() -> Vec<Self> {
                vec![ $( Self::$variant, )* ]
            }
        }
    };
}

define_msg_types! {
    /// Heartbeat (0) - Session level.
    #[default]
    Heartbeat = "0", admin = true;
    /// Test Request (1) - Session level.
    TestRequest = "1", admin = true;
    /// Resend Request (2) - Session level.
    ResendRequest = "2", admin = true;
    /// Reject (3) - Session level.
    Reject = "3", admin = true;
    /// Sequence Reset (4) - Session level.
    SequenceReset = "4", admin = true;
    /// Logout (5) - Session level.
    Logout = "5", admin = true;
    /// Indication of Interest (6).
    IndicationOfInterest = "6", admin = false;
    /// Advertisement (7).
    Advertisement = "7", admin = false;
    /// Execution Report (8).
    ExecutionReport = "8", admin = false;
    /// Order Cancel Reject (9).
    OrderCancelReject = "9", admin = false;
    /// Logon (A) - Session level.
    Logon = "A", admin = true;
    /// News (B).
    News = "B", admin = false;
    /// Email (C).
    Email = "C", admin = false;
    /// New Order Single (D).
    NewOrderSingle = "D", admin = false;
    /// New Order List (E).
    NewOrderList = "E", admin = false;
    /// Order Cancel Request (F).
    OrderCancelRequest = "F", admin = false;
    /// Order Cancel/Replace Request (G).
    OrderCancelReplaceRequest = "G", admin = false;
    /// Order Status Request (H).
    OrderStatusRequest = "H", admin = false;
    /// Allocation Instruction (J).
    AllocationInstruction = "J", admin = false;
    /// List Cancel Request (K).
    ListCancelRequest = "K", admin = false;
    /// List Execute (L).
    ListExecute = "L", admin = false;
    /// List Status Request (M).
    ListStatusRequest = "M", admin = false;
    /// List Status (N).
    ListStatus = "N", admin = false;
    /// Allocation Instruction Ack (P).
    AllocationInstructionAck = "P", admin = false;
    /// Don't Know Trade (Q).
    DontKnowTrade = "Q", admin = false;
    /// Quote Request (R).
    QuoteRequest = "R", admin = false;
    /// Quote (S).
    Quote = "S", admin = false;
    /// Settlement Instructions (T).
    SettlementInstructions = "T", admin = false;
    /// Market Data Request (V).
    MarketDataRequest = "V", admin = false;
    /// Market Data Snapshot/Full Refresh (W).
    MarketDataSnapshotFullRefresh = "W", admin = false;
    /// Market Data Incremental Refresh (X).
    MarketDataIncrementalRefresh = "X", admin = false;
    /// Market Data Request Reject (Y).
    MarketDataRequestReject = "Y", admin = false;
    /// Quote Cancel (Z).
    QuoteCancel = "Z", admin = false;
    /// Quote Status Request (a).
    QuoteStatusRequest = "a", admin = false;
    /// Mass Quote Acknowledgement (b).
    MassQuoteAcknowledgement = "b", admin = false;
    /// Security Definition Request (c).
    SecurityDefinitionRequest = "c", admin = false;
    /// Security Definition (d).
    SecurityDefinition = "d", admin = false;
    /// Security Status Request (e).
    SecurityStatusRequest = "e", admin = false;
    /// Security Status (f).
    SecurityStatus = "f", admin = false;
    /// Trading Session Status Request (g).
    TradingSessionStatusRequest = "g", admin = false;
    /// Trading Session Status (h).
    TradingSessionStatus = "h", admin = false;
    /// Mass Quote (i).
    MassQuote = "i", admin = false;
    /// Business Message Reject (j).
    BusinessMessageReject = "j", admin = false;
    /// Bid Request (k).
    BidRequest = "k", admin = false;
    /// Bid Response (l).
    BidResponse = "l", admin = false;
    /// List Strike Price (m).
    ListStrikePrice = "m", admin = false;
    /// XML Message, XMLnonFIX (n) - `msgcat='admin'` in the FIX dictionary.
    XmlMessage = "n", admin = true;
    /// Registration Instructions (o).
    RegistrationInstructions = "o", admin = false;
    /// Registration Instructions Response (p).
    RegistrationInstructionsResponse = "p", admin = false;
    /// Order Mass Cancel Request (q).
    OrderMassCancelRequest = "q", admin = false;
    /// Order Mass Cancel Report (r).
    OrderMassCancelReport = "r", admin = false;
    /// New Order Cross (s).
    NewOrderCross = "s", admin = false;
    /// Cross Order Cancel/Replace Request (t).
    CrossOrderCancelReplaceRequest = "t", admin = false;
    /// Cross Order Cancel Request (u).
    CrossOrderCancelRequest = "u", admin = false;
    /// Security Type Request (v).
    SecurityTypeRequest = "v", admin = false;
    /// Security Types (w).
    SecurityTypes = "w", admin = false;
    /// Security List Request (x).
    SecurityListRequest = "x", admin = false;
    /// Security List (y).
    SecurityList = "y", admin = false;
    /// Derivative Security List Request (z).
    DerivativeSecurityListRequest = "z", admin = false;
}

impl std::str::FromStr for MsgType {
    type Err = std::convert::Infallible;

    /// Creates a MsgType from a string value.
    ///
    /// Infallible: an unrecognised code becomes [`MsgType::Custom`], which is
    /// how a private or newer message type reaches the application layer
    /// without the decoder having to know it. Delegates to [`MsgType::new`],
    /// so the result is always in normal form.
    ///
    /// # Arguments
    /// * `s` - The message type string (e.g., "D" for NewOrderSingle)
    ///
    /// # Errors
    /// Never returns an error.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

impl MsgType {
    /// Returns true if this is an application message.
    #[must_use]
    pub fn is_app(&self) -> bool {
        !self.is_admin()
    }
}

/// Compares the on-the-wire form, not the variant.
///
/// `Custom("D")` and `NewOrderSingle` both encode `35=D`, so they compare
/// equal; anything else would make a `Custom` value miss its own entry in a
/// `MsgType`-keyed map.
impl PartialEq for MsgType {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for MsgType {}

/// Hashes the on-the-wire form, keeping `Hash` consistent with [`PartialEq`].
impl std::hash::Hash for MsgType {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
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
    /// # Borrow invariant
    ///
    /// Field offsets are recovered by subtracting the buffer's address from
    /// each field value's address, so **every `FieldRef` in `raw` must borrow
    /// from `raw.buffer()`** — which is what a decoder that produced both
    /// guarantees. A field pointing anywhere else has no offset in this
    /// buffer; rather than computing a wrapped or out-of-range one, it is
    /// **dropped**, and `field_count()` on the result is correspondingly
    /// lower. Such a `RawMessage` is a construction bug in whatever produced
    /// it, not an input this type can repair.
    ///
    /// # Arguments
    /// * `raw` - The raw message to copy
    #[must_use]
    pub fn from_raw(raw: &RawMessage<'_>) -> Self {
        let buffer = Bytes::copy_from_slice(raw.buffer);
        let buffer_start = raw.buffer.as_ptr() as usize;
        let buffer_len = raw.buffer.len();

        let mut field_offsets = Vec::with_capacity(raw.fields.len());
        for field in &raw.fields {
            let offset = (field.value.as_ptr() as usize)
                .checked_sub(buffer_start)
                .and_then(|start| {
                    let end = start.checked_add(field.value.len())?;
                    (end <= buffer_len).then_some(start..end)
                });
            if let Some(range) = offset {
                field_offsets.push((field.tag, range));
            }
        }

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

    use std::collections::hash_map::DefaultHasher;
    use std::collections::{HashMap, HashSet};
    use std::hash::{Hash, Hasher};

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
    fn test_msg_type_every_variant_round_trips_through_its_code() {
        for variant in MsgType::all_named() {
            let code = variant.as_str().to_owned();
            assert_eq!(
                MsgType::new(&code),
                variant,
                "MsgType::new({code:?}) must recover {variant:?}"
            );
            // A named code must never fall through to Custom.
            assert!(
                !matches!(MsgType::new(&code), MsgType::Custom(_)),
                "{code:?} must map to a named variant, not Custom"
            );
        }
    }

    #[test]
    fn test_msg_type_codes_are_unique() {
        let named = MsgType::all_named();
        let codes: HashSet<&str> = named.iter().map(MsgType::as_str).collect();
        assert_eq!(
            codes.len(),
            named.len(),
            "two variants share one wire code, so the reverse lookup is ambiguous"
        );
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
    fn test_msg_type_is_admin_matches_dictionary_msgcat() {
        // The eight msgtype values marked msgcat='admin' in FIX44.xml.
        const ADMIN_CODES: [&str; 8] = ["0", "1", "2", "3", "4", "5", "A", "n"];
        for variant in MsgType::all_named() {
            let expected = ADMIN_CODES.contains(&variant.as_str());
            assert_eq!(
                variant.is_admin(),
                expected,
                "{variant:?} ({}) disagrees with the dictionary msgcat",
                variant.as_str()
            );
            assert_eq!(variant.is_app(), !expected);
        }
    }

    #[test]
    fn test_msg_type_xml_message_is_admin() {
        assert_eq!(MsgType::new("n"), MsgType::XmlMessage);
        assert!(MsgType::XmlMessage.is_admin());
        assert!(!MsgType::XmlMessage.is_app());
    }

    #[test]
    fn test_msg_type_custom() {
        let custom = MsgType::Custom("XX".to_string());
        assert_eq!("XX".parse::<MsgType>(), Ok(custom.clone()));
        assert_eq!(custom.as_str(), "XX");
        assert!(!custom.is_admin());
        assert!(custom.is_app());
    }

    #[test]
    fn test_msg_type_new_normalises_known_code_out_of_custom() {
        assert_eq!(MsgType::new("D"), MsgType::NewOrderSingle);
        assert!(matches!(MsgType::new("D"), MsgType::NewOrderSingle));
        assert!(matches!(MsgType::new("ZZ"), MsgType::Custom(_)));
    }

    #[test]
    fn test_msg_type_custom_equals_named_variant_with_same_wire_form() {
        let custom = MsgType::Custom("D".to_string());
        assert_eq!(custom, MsgType::NewOrderSingle);
        assert_eq!(MsgType::NewOrderSingle, custom);
        assert_ne!(custom, MsgType::ExecutionReport);
    }

    #[test]
    fn test_msg_type_equal_values_agree_on_is_admin() {
        // Equality follows the wire form, so classification must too — a
        // Custom("A") that routed as an application message while an equal
        // MsgType::Logon routed as admin would be a session-layer split brain.
        for variant in MsgType::all_named() {
            let as_custom = MsgType::Custom(variant.as_str().to_owned());
            assert_eq!(as_custom, variant);
            assert_eq!(
                as_custom.is_admin(),
                variant.is_admin(),
                "Custom({:?}) must classify like {variant:?}",
                variant.as_str()
            );
        }
        // A code no variant names stays an application message.
        assert!(!MsgType::Custom("ZZ".to_owned()).is_admin());
    }

    #[test]
    fn test_msg_type_hash_follows_wire_form() {
        fn hash_of(value: &MsgType) -> u64 {
            let mut hasher = DefaultHasher::new();
            value.hash(&mut hasher);
            hasher.finish()
        }
        let custom = MsgType::Custom("D".to_string());
        assert_eq!(hash_of(&custom), hash_of(&MsgType::NewOrderSingle));

        let mut map: HashMap<MsgType, u32> = HashMap::new();
        map.insert(MsgType::NewOrderSingle, 1);
        assert_eq!(map.get(&custom), Some(&1));
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
    fn test_owned_message_from_raw_recovers_buffer_offsets() {
        let buffer: &[u8] = b"8=FIX.4.4\x0135=D\x0149=SENDER\x01";
        let mut fields: SmallVec<[FieldRef<'_>; 32]> = SmallVec::new();
        let Some(begin) = buffer.get(2..9) else {
            panic!("fixture buffer is long enough")
        };
        let Some(sender) = buffer.get(18..24) else {
            panic!("fixture buffer is long enough")
        };
        fields.push(FieldRef::new(8, begin));
        fields.push(FieldRef::new(49, sender));
        let Ok(raw) = RawMessage::new(buffer, 2..9, 10..24, MsgType::NewOrderSingle, fields) else {
            panic!("in-bounds ranges must be accepted");
        };

        let owned = OwnedMessage::from_raw(&raw);
        assert_eq!(owned.field_count(), 2);
        assert_eq!(owned.get_field_str(8), Some("FIX.4.4"));
        assert_eq!(owned.get_field_str(49), Some("SENDER"));
    }

    #[test]
    fn test_owned_message_from_raw_drops_field_not_borrowing_from_buffer() {
        let buffer: &[u8] = b"8=FIX.4.4\x0135=D\x01";
        // Deliberately borrowed from a different allocation: the offset of
        // this value inside `buffer` does not exist, and the old pointer
        // subtraction would have wrapped into a huge range.
        let foreign: &[u8] = b"FOREIGN";
        let mut fields: SmallVec<[FieldRef<'_>; 32]> = SmallVec::new();
        let Some(begin) = buffer.get(2..9) else {
            panic!("fixture buffer is long enough")
        };
        fields.push(FieldRef::new(8, begin));
        fields.push(FieldRef::new(49, foreign));
        let Ok(raw) = RawMessage::new(buffer, 2..9, 10..15, MsgType::NewOrderSingle, fields) else {
            panic!("in-bounds ranges must be accepted");
        };

        let owned = OwnedMessage::from_raw(&raw);
        assert_eq!(owned.field_count(), 1);
        assert_eq!(owned.get_field_str(8), Some("FIX.4.4"));
        assert_eq!(owned.get_field(49), None);
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
