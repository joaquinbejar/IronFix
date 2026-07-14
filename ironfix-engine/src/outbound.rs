/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Outbound application message builder.

use ironfix_core::message::MsgType;

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
    fields: Vec<(u32, Vec<u8>)>,
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
        self.fields.push((tag, value.into()));
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
    pub fn fields(&self) -> &[(u32, Vec<u8>)] {
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
        assert_eq!(fields[0], (11, b"ORDER-1".to_vec()));
        assert_eq!(fields[1], (54, b"1".to_vec()));
        assert_eq!(fields[2], (38, b"100".to_vec()));
        assert_eq!(fields[3], (9999, b"-5".to_vec()));
        assert_eq!(fields[4], (59, b"Y".to_vec()));
    }
}
