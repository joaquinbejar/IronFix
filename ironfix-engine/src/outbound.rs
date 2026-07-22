/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Outbound application message builder.

use ironfix_core::message::MsgType;

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

/// An outbound application message: a MsgType plus ordered body fields.
///
/// The engine stamps the standard header (BeginString, BodyLength, MsgType,
/// SenderCompID, TargetCompID, MsgSeqNum, SendingTime) and the trailer when
/// the message is sent, so the builder only carries body fields. Fields are
/// encoded in insertion order.
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    /// Message type (tag 35).
    msg_type: MsgType,
    /// Body fields in insertion order.
    fields: Vec<OutboundField>,
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
}
