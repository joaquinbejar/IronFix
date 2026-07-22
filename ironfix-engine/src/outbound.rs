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
//! [`Application::to_app`](crate::Application::to_app) and
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

use crate::error::EngineError;
use ironfix_core::message::MsgType;
use ironfix_tagvalue::SOH;

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
/// [`Application::to_app`](crate::Application::to_app) receive this type by
/// `&mut` **before** the header is stamped and before a sequence number is
/// spent, so a field added there is encoded into the frame that goes out. The
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
#[derive(Clone)]
pub struct OutboundMessage {
    /// Message type (tag 35).
    msg_type: MsgType,
    /// Body fields in insertion order.
    fields: Vec<OutboundField>,
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
        }
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
        self.push_raw(tag, value.as_bytes().to_vec())
    }

    /// Appends a field with an integer value.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value
    pub fn push_int(&mut self, tag: u32, value: i64) -> &mut Self {
        self.push_raw(tag, value.to_string().into_bytes())
    }

    /// Appends a field with an unsigned integer value.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value
    pub fn push_uint(&mut self, tag: u32, value: u64) -> &mut Self {
        self.push_raw(tag, value.to_string().into_bytes())
    }

    /// Appends a field with a single character value.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value
    pub fn push_char(&mut self, tag: u32, value: char) -> &mut Self {
        let mut buf = [0u8; 4];
        let s = value.encode_utf8(&mut buf);
        self.push_raw(tag, s.as_bytes().to_vec())
    }

    /// Appends a field with a boolean value (Y/N).
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value
    pub fn push_bool(&mut self, tag: u32, value: bool) -> &mut Self {
        self.push_raw(tag, if value { b"Y".to_vec() } else { b"N".to_vec() })
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
    /// `DATA` tag matches, so the counted halves never survive apart.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    pub fn remove(&mut self, tag: u32) -> usize {
        let before = self.fields.len();
        self.fields.retain(|field| match field {
            OutboundField::Raw { tag: field_tag, .. } => *field_tag != tag,
            OutboundField::Data {
                length_tag,
                data_tag,
                ..
            } => *length_tag != tag && *data_tag != tag,
        });
        before - self.fields.len()
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
}
