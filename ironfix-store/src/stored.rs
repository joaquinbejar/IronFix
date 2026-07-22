/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! The unit a [`MessageStore`](crate::MessageStore) hands back.
//!
//! A store exists so a `ResendRequest` (35=2) can be answered with the traffic
//! that was actually sent. That makes faithfulness the whole contract: what
//! comes out has to be what went in, still carrying the sequence number it was
//! filed under and the `MsgType` it was sent as.
//!
//! [`StoredMessage`] therefore keeps the **verbatim frame bytes** rather than a
//! parsed representation. `ironfix-store` depends on `ironfix-core` only — it
//! has no decoder, so any structure it claimed to recover would be invented.
//! The composition root (`ironfix-engine`) owns the decoder and re-reads the
//! bytes when it needs fields.

use bytes::Bytes;
use ironfix_core::message::MsgType;

/// One message as it was filed, returned by
/// [`MessageStore::get_range`](crate::MessageStore::get_range).
///
/// The payload is the complete frame that went on the wire, including
/// `BeginString` (8), `BodyLength` (9) and `CheckSum` (10). A resend rebuilds
/// from it — stamping `PossDupFlag` (43) and `OrigSendingTime` (122) — so it
/// must not be a reconstruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    /// The `MsgSeqNum` (34) this message was filed under.
    seq_num: u64,
    /// The `MsgType` (35) it was sent as, recorded at store time.
    msg_type: MsgType,
    /// The verbatim frame bytes.
    payload: Bytes,
}

impl StoredMessage {
    /// Creates a stored message from its sequence number, type and frame.
    ///
    /// # Arguments
    /// * `seq_num` - The `MsgSeqNum` (34) the message was sent under
    /// * `msg_type` - The `MsgType` (35) the message was sent as
    /// * `payload` - The complete frame bytes
    #[must_use]
    pub const fn new(seq_num: u64, msg_type: MsgType, payload: Bytes) -> Self {
        Self {
            seq_num,
            msg_type,
            payload,
        }
    }

    /// Returns the sequence number this message was filed under.
    #[must_use]
    pub const fn seq_num(&self) -> u64 {
        self.seq_num
    }

    /// Returns the message type recorded at store time.
    #[must_use]
    pub const fn msg_type(&self) -> &MsgType {
        &self.msg_type
    }

    /// Returns the verbatim frame bytes.
    #[must_use]
    pub const fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// Consumes the message and returns its frame bytes.
    #[must_use]
    pub fn into_payload(self) -> Bytes {
        self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_message_accessors_return_what_was_stored() {
        let message = StoredMessage::new(
            7,
            MsgType::NewOrderSingle,
            Bytes::from_static(b"8=FIX.4.4\x0135=D\x01"),
        );

        assert_eq!(message.seq_num(), 7);
        assert_eq!(message.msg_type(), &MsgType::NewOrderSingle);
        assert_eq!(&message.payload()[..], b"8=FIX.4.4\x0135=D\x01");
    }

    #[test]
    fn test_stored_message_into_payload_returns_verbatim_bytes() {
        let message = StoredMessage::new(1, MsgType::Logon, Bytes::from_static(b"8=FIX.4.4\x01"));

        assert_eq!(&message.into_payload()[..], b"8=FIX.4.4\x01");
    }
}
