/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Internal helpers for building and parsing FIX frames.
//!
//! Admin messages (Logon, Heartbeat, TestRequest, Logout, ResendRequest,
//! SequenceReset, Reject) are constructed here with the standard header
//! stamped from the session configuration. Application messages built by
//! consumers via [`OutboundMessage`] get the same header treatment.

use crate::application::RejectReason;
use crate::outbound::OutboundMessage;
use bytes::BytesMut;
use ironfix_core::error::DecodeError;
use ironfix_core::message::{OwnedMessage, RawMessage};
use ironfix_core::types::Timestamp;
use ironfix_session::SessionConfig;
use ironfix_tagvalue::{Decoder, Encoder};

/// Returns a `'static` copy of a FIX BeginString.
///
/// Well-known versions map to interned constants; anything else is leaked
/// once (bounded: once per `Initiator`), because the tag-value `Encoder`
/// requires a `&'static str` BeginString.
pub(crate) fn static_begin_string(value: &str) -> &'static str {
    match value {
        "FIX.4.0" => "FIX.4.0",
        "FIX.4.1" => "FIX.4.1",
        "FIX.4.2" => "FIX.4.2",
        "FIX.4.3" => "FIX.4.3",
        "FIX.4.4" => "FIX.4.4",
        "FIX.5.0" => "FIX.5.0",
        "FIX.5.0SP1" => "FIX.5.0SP1",
        "FIX.5.0SP2" => "FIX.5.0SP2",
        "FIXT.1.1" => "FIXT.1.1",
        other => Box::leak(other.to_owned().into_boxed_str()),
    }
}

/// Decodes a framed FIX message.
///
/// Checksum validation is skipped: the transport codec has already
/// validated the frame when configured to do so.
pub(crate) fn decode_frame(frame: &[u8]) -> Result<RawMessage<'_>, DecodeError> {
    let mut decoder = Decoder::new(frame).with_checksum_validation(false);
    decoder.decode()
}

/// Decodes a frame into an [`OwnedMessage`] for the `to_admin`/`to_app`
/// application callbacks.
pub(crate) fn owned_from_frame(frame: &[u8]) -> Result<OwnedMessage, DecodeError> {
    Ok(decode_frame(frame)?.to_owned())
}

/// Builds outbound frames with the session header stamped.
#[derive(Debug)]
pub(crate) struct MessageFactory {
    begin_string: &'static str,
    sender_comp_id: String,
    target_comp_id: String,
    sender_sub_id: Option<String>,
    target_sub_id: Option<String>,
}

impl MessageFactory {
    /// Creates a factory from the session configuration.
    pub(crate) fn new(config: &SessionConfig, begin_string: &'static str) -> Self {
        Self {
            begin_string,
            sender_comp_id: config.sender_comp_id.as_str().to_string(),
            target_comp_id: config.target_comp_id.as_str().to_string(),
            sender_sub_id: config.sender_sub_id.clone(),
            target_sub_id: config.target_sub_id.clone(),
        }
    }

    /// Starts an encoder with the standard header:
    /// 35, 49, 56, [50], [57], 34, [43], 52.
    fn header(&self, msg_type: &str, seq: u64, poss_dup: bool) -> Encoder {
        let mut encoder = Encoder::new(self.begin_string);
        encoder.put_str(35, msg_type);
        encoder.put_str(49, &self.sender_comp_id);
        encoder.put_str(56, &self.target_comp_id);
        if let Some(sub) = &self.sender_sub_id {
            encoder.put_str(50, sub);
        }
        if let Some(sub) = &self.target_sub_id {
            encoder.put_str(57, sub);
        }
        encoder.put_uint(34, seq);
        if poss_dup {
            encoder.put_bool(43, true);
        }
        encoder.put_str(52, Timestamp::now().format_millis().as_str());
        encoder
    }

    /// Builds a Logon (35=A) with EncryptMethod=0 and HeartBtInt.
    pub(crate) fn logon(&self, seq: u64, heartbeat_secs: u64, reset_seq: bool) -> BytesMut {
        let mut encoder = self.header("A", seq, false);
        encoder.put_uint(98, 0);
        encoder.put_uint(108, heartbeat_secs);
        if reset_seq {
            encoder.put_bool(141, true);
        }
        encoder.finish()
    }

    /// Builds a Heartbeat (35=0), echoing TestReqID (112) when replying to
    /// a TestRequest.
    pub(crate) fn heartbeat(&self, seq: u64, test_req_id: Option<&str>) -> BytesMut {
        let mut encoder = self.header("0", seq, false);
        if let Some(id) = test_req_id {
            encoder.put_str(112, id);
        }
        encoder.finish()
    }

    /// Builds a TestRequest (35=1) with TestReqID (112).
    pub(crate) fn test_request(&self, seq: u64, test_req_id: &str) -> BytesMut {
        let mut encoder = self.header("1", seq, false);
        encoder.put_str(112, test_req_id);
        encoder.finish()
    }

    /// Builds a Logout (35=5) with optional Text (58).
    pub(crate) fn logout(&self, seq: u64, text: Option<&str>) -> BytesMut {
        let mut encoder = self.header("5", seq, false);
        if let Some(text) = text {
            encoder.put_str(58, text);
        }
        encoder.finish()
    }

    /// Builds a ResendRequest (35=2) for `begin_seq..end_seq`
    /// (`end_seq` = 0 means "up to infinity").
    pub(crate) fn resend_request(&self, seq: u64, begin_seq: u64, end_seq: u64) -> BytesMut {
        let mut encoder = self.header("2", seq, false);
        encoder.put_uint(7, begin_seq);
        encoder.put_uint(16, end_seq);
        encoder.finish()
    }

    /// Builds a SequenceReset-GapFill (35=4, 123=Y) that answers a
    /// ResendRequest by jumping the counterparty's expectation to `new_seq`.
    /// Stamped with the gap's begin sequence and PossDupFlag (43=Y).
    pub(crate) fn sequence_reset_gap_fill(&self, seq: u64, new_seq: u64) -> BytesMut {
        let mut encoder = self.header("4", seq, true);
        encoder.put_bool(123, true);
        encoder.put_uint(36, new_seq);
        encoder.finish()
    }

    /// Builds a session-level Reject (35=3).
    pub(crate) fn session_reject(
        &self,
        seq: u64,
        ref_seq: u64,
        ref_msg_type: &str,
        reason: &RejectReason,
    ) -> BytesMut {
        let mut encoder = self.header("3", seq, false);
        encoder.put_uint(45, ref_seq);
        if let Some(ref_tag) = reason.ref_tag {
            encoder.put_uint(371, u64::from(ref_tag));
        }
        encoder.put_str(372, ref_msg_type);
        encoder.put_uint(373, u64::from(reason.code));
        if !reason.text.is_empty() {
            encoder.put_str(58, &reason.text);
        }
        encoder.finish()
    }

    /// Builds an application message from an [`OutboundMessage`].
    pub(crate) fn application_message(&self, seq: u64, message: &OutboundMessage) -> BytesMut {
        let mut encoder = self.header(message.msg_type().as_str(), seq, false);
        for (tag, value) in message.fields() {
            encoder.put_raw(*tag, value);
        }
        encoder.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironfix_core::message::MsgType;
    use ironfix_core::types::CompId;

    fn factory() -> MessageFactory {
        let config = SessionConfig::new(
            CompId::new("CLIENT").unwrap(),
            CompId::new("VENUE").unwrap(),
            "FIX.4.4",
        );
        MessageFactory::new(&config, static_begin_string(&config.begin_string))
    }

    #[test]
    fn test_logon_frame_roundtrip() {
        let frame = factory().logon(1, 30, true);
        let raw = decode_frame(&frame).unwrap();
        assert_eq!(raw.msg_type(), &MsgType::Logon);
        assert_eq!(raw.get_field_str(49), Some("CLIENT"));
        assert_eq!(raw.get_field_str(56), Some("VENUE"));
        assert_eq!(raw.get_field_str(34), Some("1"));
        assert_eq!(raw.get_field_str(98), Some("0"));
        assert_eq!(raw.get_field_str(108), Some("30"));
        assert_eq!(raw.get_field_str(141), Some("Y"));
    }

    #[test]
    fn test_gap_fill_frame() {
        let frame = factory().sequence_reset_gap_fill(3, 10);
        let raw = decode_frame(&frame).unwrap();
        assert_eq!(raw.msg_type(), &MsgType::SequenceReset);
        assert_eq!(raw.get_field_str(34), Some("3"));
        assert_eq!(raw.get_field_str(43), Some("Y"));
        assert_eq!(raw.get_field_str(123), Some("Y"));
        assert_eq!(raw.get_field_str(36), Some("10"));
    }

    #[test]
    fn test_application_message_frame() {
        let mut message = OutboundMessage::new(MsgType::NewOrderSingle);
        message.push_str(11, "ORDER-1").push_char(54, '1');

        let frame = factory().application_message(7, &message);
        let raw = decode_frame(&frame).unwrap();
        assert_eq!(raw.msg_type(), &MsgType::NewOrderSingle);
        assert_eq!(raw.get_field_str(34), Some("7"));
        assert_eq!(raw.get_field_str(11), Some("ORDER-1"));
        assert_eq!(raw.get_field_str(54), Some("1"));
    }

    #[test]
    fn test_static_begin_string_interned() {
        assert_eq!(static_begin_string("FIX.4.4"), "FIX.4.4");
        assert_eq!(static_begin_string("FIX.9.9"), "FIX.9.9");
    }
}
