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
use crate::outbound::{OutboundField, OutboundMessage};
use bytes::BytesMut;
use ironfix_core::error::{DecodeError, EncodeError};
use ironfix_core::message::{OwnedMessage, RawMessage};
use ironfix_core::types::Timestamp;
use ironfix_core::version::FixVersion;
use ironfix_session::SessionConfig;
use ironfix_tagvalue::{Decoder, Encoder};

/// A configured `BeginString` the engine cannot frame conformantly.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unsupported FIX version {version}: {detail}")]
pub(crate) struct UnsupportedVersion {
    /// The configured version string.
    pub(crate) version: String,
    /// Why it cannot be framed.
    pub(crate) detail: String,
}

/// Resolves the configured version string to the [`FixVersion`] whose wire
/// representation the header stamper uses.
///
/// The version-to-wire mapping — `BeginString` (8), and the application
/// version for `DefaultApplVerID` (1137) and `ApplVerID` (1128) — belongs to
/// [`FixVersion`] in `ironfix-core`, which is the workspace's single copy of
/// it. This function only decides whether a configured string names a version
/// the engine can frame; it does not restate the table.
///
/// Two strings are refused:
///
/// - one that names no version at all, which has no `BeginString` to stamp;
/// - bare `FIXT.1.1`, which names the transport version only. A FIXT Logon
///   must carry `DefaultApplVerID` (1137), which is **required**, and the
///   application version is exactly what this string failed to state.
///   Defaulting it would put a guessed version on the wire, so the session is
///   refused instead — configure `FIX.5.0`, `FIX.5.0SP1` or `FIX.5.0SP2`.
///
/// # Errors
/// Returns [`UnsupportedVersion`] in either of those cases.
pub(crate) fn wire_version(value: &str) -> Result<FixVersion, UnsupportedVersion> {
    let version: FixVersion = value.parse().map_err(|_| UnsupportedVersion {
        version: value.to_owned(),
        detail: format!(
            "not a FIX version this engine can frame; supported values are {}",
            framable_versions()
        ),
    })?;

    if version.uses_fixt() && version.appl_ver_id().is_none() {
        return Err(UnsupportedVersion {
            version: value.to_owned(),
            detail: format!(
                "{version} names only the transport version and carries no application version \
                 for DefaultApplVerID (1137), which a FIXT Logon requires; supported values are {}",
                framable_versions()
            ),
        });
    }

    Ok(version)
}

/// Lists the versions [`wire_version`] accepts, derived from [`FixVersion`] so
/// the message cannot go stale when a version is added.
fn framable_versions() -> String {
    FixVersion::ALL
        .into_iter()
        .filter(|version| !(version.uses_fixt() && version.appl_ver_id().is_none()))
        .map(FixVersion::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A mismatch between an inbound message's identity fields and the
/// configured counterparty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdentityMismatch {
    /// The offending tag (49, 56, 50 or 57).
    pub(crate) tag: u32,
    /// The value the configuration requires.
    pub(crate) expected: String,
    /// The value the counterparty sent, empty when the tag was absent.
    pub(crate) received: String,
}

impl std::fmt::Display for IdentityMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CompID problem: tag {} expected '{}', received '{}'",
            self.tag, self.expected, self.received
        )
    }
}

/// The identity every inbound message must carry, derived from the session
/// configuration with sender and target reversed.
///
/// A cross-wired connection that is never checked advances sequence state
/// against the wrong counterparty and delivers another session's traffic to
/// the application, so this is validated before anything else touches
/// session state. A mismatch is `SessionRejectReason` 9, "CompID problem"
/// (`doc/fix_operations.md`, "Session Reject Reasons").
#[derive(Debug, Clone)]
pub(crate) struct PeerIdentity {
    /// Required inbound `SenderCompID` (49) — our configured target.
    sender_comp_id: String,
    /// Required inbound `TargetCompID` (56) — our configured sender.
    target_comp_id: String,
    /// Required inbound `SenderSubID` (50), when configured.
    sender_sub_id: Option<String>,
    /// Required inbound `TargetSubID` (57), when configured.
    target_sub_id: Option<String>,
}

impl PeerIdentity {
    /// Builds the expected inbound identity from the session configuration.
    #[must_use]
    pub(crate) fn new(config: &SessionConfig) -> Self {
        Self {
            sender_comp_id: config.target_comp_id.as_str().to_string(),
            target_comp_id: config.sender_comp_id.as_str().to_string(),
            sender_sub_id: config.target_sub_id.clone(),
            target_sub_id: config.sender_sub_id.clone(),
        }
    }

    /// Checks an inbound message's identity fields.
    ///
    /// Sub IDs are only checked when configured; an unconfigured sub ID
    /// places no requirement on the counterparty.
    /// # Positional caveat
    ///
    /// Field lookup is by tag over the whole decoded message, not by position,
    /// so CompIDs appearing anywhere in the frame satisfy the check. A message
    /// that omits them from the standard header but carries them in the body is
    /// therefore accepted. Enforcing header position needs positional
    /// information the decoder does not currently retain; the practical impact
    /// is small, since a peer able to place the tags in the body can equally
    /// place them in the header.
    pub(crate) fn validate(&self, raw: &RawMessage<'_>) -> Result<(), IdentityMismatch> {
        check_field(raw, 49, &self.sender_comp_id)?;
        check_field(raw, 56, &self.target_comp_id)?;
        if let Some(expected) = &self.sender_sub_id {
            check_field(raw, 50, expected)?;
        }
        if let Some(expected) = &self.target_sub_id {
            check_field(raw, 57, expected)?;
        }
        Ok(())
    }
}

/// Compares one inbound identity field against its required value.
fn check_field(raw: &RawMessage<'_>, tag: u32, expected: &str) -> Result<(), IdentityMismatch> {
    let received = raw.get_field_str(tag).unwrap_or_default();
    if received == expected {
        Ok(())
    } else {
        Err(IdentityMismatch {
            tag,
            expected: expected.to_string(),
            received: received.to_string(),
        })
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

/// Stamps the frame and moves it into a buffer the transport owns.
///
/// # Errors
/// Returns the [`EncodeError`] the encoder recorded — a field value that
/// cannot be represented on the wire, such as a `Text` (58) carrying the SOH
/// delimiter or an empty `TestReqID` (112) echoed back from a peer. A frame is
/// never produced from a rejected value.
fn into_frame(encoder: &mut Encoder) -> Result<BytesMut, EncodeError> {
    let mut frame = BytesMut::new();
    encoder.finish_into(&mut frame)?;
    Ok(frame)
}

/// Builds outbound frames with the session header stamped.
#[derive(Debug)]
pub(crate) struct MessageFactory {
    version: FixVersion,
    sender_comp_id: String,
    target_comp_id: String,
    sender_sub_id: Option<String>,
    target_sub_id: Option<String>,
    sender_location_id: Option<String>,
    target_location_id: Option<String>,
}

impl MessageFactory {
    /// Creates a factory from the session configuration.
    #[must_use]
    pub(crate) fn new(config: &SessionConfig, version: FixVersion) -> Self {
        Self {
            version,
            sender_comp_id: config.sender_comp_id.as_str().to_string(),
            target_comp_id: config.target_comp_id.as_str().to_string(),
            sender_sub_id: config.sender_sub_id.clone(),
            target_sub_id: config.target_sub_id.clone(),
            sender_location_id: config.sender_location_id.clone(),
            target_location_id: config.target_location_id.clone(),
        }
    }

    /// Starts an encoder with the standard header:
    /// 35, [1128], 49, 56, [50], [142], [57], [143], 34, [43], 52, [122].
    ///
    /// `SenderLocationID` (142) follows `SenderSubID` (50) and
    /// `TargetLocationID` (143) follows `TargetSubID` (57), the standard-header
    /// pairing of the routing fields. Both are stamped only when configured;
    /// an unset LocationID places nothing on the wire.
    ///
    /// `poss_dup` stamps both `PossDupFlag` (43) and `OrigSendingTime` (122):
    /// FIX requires 122 on every message carrying 43=Y, and
    /// `doc/fix_operations.md` mandates it for resends. The engine has no
    /// message store, so the original sending time of the replaced messages
    /// is not recoverable; per the spec's handling of an unavailable
    /// OrigSendingTime the current time is used, which is also what a
    /// SequenceReset-GapFill (whose "original" messages are administrative
    /// filler, not replayed traffic) needs.
    ///
    /// `appl_ver_id` stamps `ApplVerID` (1128) immediately after MsgType,
    /// its position in the FIXT.1.1 standard header. It is passed only for
    /// application messages; session-level messages are versioned by the
    /// FIXT.1.1 BeginString itself.
    fn header(
        &self,
        msg_type: &str,
        seq: u64,
        poss_dup: bool,
        appl_ver_id: Option<&str>,
    ) -> Encoder {
        let mut encoder = Encoder::new(self.version.begin_string());
        encoder.put_str(35, msg_type);
        if let Some(appl_ver_id) = appl_ver_id {
            encoder.put_str(1128, appl_ver_id);
        }
        encoder.put_str(49, &self.sender_comp_id);
        encoder.put_str(56, &self.target_comp_id);
        if let Some(sub) = &self.sender_sub_id {
            encoder.put_str(50, sub);
        }
        if let Some(location) = &self.sender_location_id {
            encoder.put_str(142, location);
        }
        if let Some(sub) = &self.target_sub_id {
            encoder.put_str(57, sub);
        }
        if let Some(location) = &self.target_location_id {
            encoder.put_str(143, location);
        }
        encoder.put_uint(34, seq);
        if poss_dup {
            encoder.put_bool(43, true);
        }
        let sending_time = Timestamp::now().format_millis();
        encoder.put_str(52, sending_time.as_str());
        if poss_dup {
            encoder.put_str(122, sending_time.as_str());
        }
        encoder
    }

    /// Builds a Logon (35=A) with EncryptMethod=0, HeartBtInt and, for a
    /// FIXT.1.1 session, DefaultApplVerID (1137).
    pub(crate) fn logon(
        &self,
        seq: u64,
        heartbeat_secs: u64,
        reset_seq: bool,
    ) -> Result<BytesMut, EncodeError> {
        let mut encoder = self.header("A", seq, false, None);
        encoder.put_uint(98, 0);
        encoder.put_uint(108, heartbeat_secs);
        if reset_seq {
            encoder.put_bool(141, true);
        }
        if let Some(appl_ver_id) = self.version.appl_ver_id() {
            encoder.put_str(1137, appl_ver_id);
        }
        into_frame(&mut encoder)
    }

    /// Builds a Heartbeat (35=0), echoing TestReqID (112) when replying to
    /// a TestRequest.
    pub(crate) fn heartbeat(
        &self,
        seq: u64,
        test_req_id: Option<&str>,
    ) -> Result<BytesMut, EncodeError> {
        let mut encoder = self.header("0", seq, false, None);
        if let Some(id) = test_req_id {
            encoder.put_str(112, id);
        }
        into_frame(&mut encoder)
    }

    /// Builds a TestRequest (35=1) with TestReqID (112).
    pub(crate) fn test_request(
        &self,
        seq: u64,
        test_req_id: &str,
    ) -> Result<BytesMut, EncodeError> {
        let mut encoder = self.header("1", seq, false, None);
        encoder.put_str(112, test_req_id);
        into_frame(&mut encoder)
    }

    /// Builds a Logout (35=5) with optional Text (58).
    pub(crate) fn logout(&self, seq: u64, text: Option<&str>) -> Result<BytesMut, EncodeError> {
        let mut encoder = self.header("5", seq, false, None);
        if let Some(text) = text {
            encoder.put_str(58, text);
        }
        into_frame(&mut encoder)
    }

    /// Builds a ResendRequest (35=2) for `begin_seq..end_seq`
    /// (`end_seq` = 0 means "up to infinity").
    pub(crate) fn resend_request(
        &self,
        seq: u64,
        begin_seq: u64,
        end_seq: u64,
    ) -> Result<BytesMut, EncodeError> {
        let mut encoder = self.header("2", seq, false, None);
        encoder.put_uint(7, begin_seq);
        encoder.put_uint(16, end_seq);
        into_frame(&mut encoder)
    }

    /// Builds a SequenceReset-GapFill (35=4, 123=Y) that answers a
    /// ResendRequest by jumping the counterparty's expectation to `new_seq`.
    /// Stamped with the gap's begin sequence, PossDupFlag (43=Y) and
    /// OrigSendingTime (122).
    pub(crate) fn sequence_reset_gap_fill(
        &self,
        seq: u64,
        new_seq: u64,
    ) -> Result<BytesMut, EncodeError> {
        let mut encoder = self.header("4", seq, true, None);
        encoder.put_bool(123, true);
        encoder.put_uint(36, new_seq);
        into_frame(&mut encoder)
    }

    /// Builds a session-level Reject (35=3).
    pub(crate) fn session_reject(
        &self,
        seq: u64,
        ref_seq: u64,
        ref_msg_type: &str,
        reason: &RejectReason,
    ) -> Result<BytesMut, EncodeError> {
        let mut encoder = self.header("3", seq, false, None);
        encoder.put_uint(45, ref_seq);
        if let Some(ref_tag) = reason.ref_tag {
            encoder.put_uint(371, u64::from(ref_tag));
        }
        encoder.put_str(372, ref_msg_type);
        encoder.put_uint(373, u64::from(reason.code));
        if !reason.text.is_empty() {
            encoder.put_str(58, &reason.text);
        }
        into_frame(&mut encoder)
    }

    /// Builds an application message from an [`OutboundMessage`], stamping
    /// ApplVerID (1128) for a FIXT.1.1 session.
    pub(crate) fn application_message(
        &self,
        seq: u64,
        message: &OutboundMessage,
    ) -> Result<BytesMut, EncodeError> {
        let mut encoder = self.header(
            message.msg_type().as_str(),
            seq,
            false,
            self.version.appl_ver_id(),
        );
        for field in message.fields() {
            match field {
                OutboundField::Raw { tag, value } => encoder.put_raw(*tag, value),
                OutboundField::Data {
                    length_tag,
                    data_tag,
                    value,
                } => encoder.put_data(*length_tag, *data_tag, value),
            }
        }
        into_frame(&mut encoder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironfix_core::message::MsgType;
    use ironfix_core::types::CompId;

    fn config_for(begin_string: &str) -> SessionConfig {
        let Ok(sender) = CompId::new("CLIENT") else {
            unreachable!("CLIENT is a valid CompId")
        };
        let Ok(target) = CompId::new("VENUE") else {
            unreachable!("VENUE is a valid CompId")
        };
        SessionConfig::new(sender, target, begin_string)
    }

    fn factory_for(begin_string: &str) -> MessageFactory {
        let config = config_for(begin_string);
        match wire_version(&config.begin_string) {
            Ok(version) => MessageFactory::new(&config, version),
            Err(err) => panic!("test fixture uses an unsupported version: {err}"),
        }
    }

    fn factory() -> MessageFactory {
        factory_for("FIX.4.4")
    }

    fn decode(frame: &[u8]) -> RawMessage<'_> {
        match decode_frame(frame) {
            Ok(raw) => raw,
            Err(err) => unreachable!("factory frame must decode: {err}"),
        }
    }

    /// Unwraps a factory frame, failing the test with the encoder's rejection.
    #[track_caller]
    fn framed(frame: Result<BytesMut, EncodeError>) -> BytesMut {
        match frame {
            Ok(frame) => frame,
            Err(err) => panic!("factory frame must encode: {err}"),
        }
    }

    #[test]
    fn test_logon_frame_roundtrip() {
        let frame = framed(factory().logon(1, 30, true));
        let raw = decode(&frame);
        assert_eq!(raw.msg_type(), &MsgType::Logon);
        assert_eq!(raw.get_field_str(49), Some("CLIENT"));
        assert_eq!(raw.get_field_str(56), Some("VENUE"));
        assert_eq!(raw.get_field_str(34), Some("1"));
        assert_eq!(raw.get_field_str(98), Some("0"));
        assert_eq!(raw.get_field_str(108), Some("30"));
        assert_eq!(raw.get_field_str(141), Some("Y"));
        // Pre-5.0 session: no application version fields.
        assert_eq!(raw.get_field_str(1137), None);
    }

    #[test]
    fn test_gap_fill_frame_carries_orig_sending_time() {
        let frame = framed(factory().sequence_reset_gap_fill(3, 10));
        let raw = decode(&frame);
        assert_eq!(raw.msg_type(), &MsgType::SequenceReset);
        assert_eq!(raw.get_field_str(34), Some("3"));
        assert_eq!(raw.get_field_str(43), Some("Y"));
        assert_eq!(raw.get_field_str(123), Some("Y"));
        assert_eq!(raw.get_field_str(36), Some("10"));
        // Every frame carrying PossDupFlag must carry OrigSendingTime, and
        // absent a store it equals SendingTime.
        assert_eq!(raw.get_field_str(122), raw.get_field_str(52));
        assert!(raw.get_field_str(122).is_some());
    }

    #[test]
    fn test_non_poss_dup_frame_omits_orig_sending_time() {
        let frame = framed(factory().heartbeat(4, None));
        let raw = decode(&frame);
        assert_eq!(raw.get_field_str(43), None);
        assert_eq!(raw.get_field_str(122), None);
    }

    #[test]
    fn test_application_message_frame() {
        let mut message = OutboundMessage::new(MsgType::NewOrderSingle);
        message.push_str(11, "ORDER-1").push_char(54, '1');

        let frame = framed(factory().application_message(7, &message));
        let raw = decode(&frame);
        assert_eq!(raw.msg_type(), &MsgType::NewOrderSingle);
        assert_eq!(raw.get_field_str(34), Some("7"));
        assert_eq!(raw.get_field_str(11), Some("ORDER-1"));
        assert_eq!(raw.get_field_str(54), Some("1"));
        assert_eq!(raw.get_field_str(1128), None);
    }

    #[test]
    fn test_application_message_encodes_raw_data_as_a_counted_pair() {
        // A RawData payload carrying SOH is routed through the encoder's
        // LENGTH/DATA path, not put_raw, so the frame encodes and the payload
        // survives byte-exact instead of the message being refused.
        let payload: &[u8] = b"a\x01b=c";
        let mut message = OutboundMessage::new(MsgType::NewOrderSingle);
        message
            .push_str(11, "ORDER-1")
            .push_data(95, 96, payload.to_vec());

        let frame = framed(factory().application_message(7, &message));
        let raw = decode(&frame);
        assert_eq!(raw.get_field_str(11), Some("ORDER-1"));
        assert_eq!(raw.get_field(95).map(|f| f.value), Some(b"5".as_slice()));
        assert_eq!(raw.get_field(96).map(|f| f.value), Some(payload));
    }

    #[test]
    fn test_header_stamps_configured_location_ids() {
        let mut config = config_for("FIX.4.4");
        config.sender_location_id = Some("LON".to_string());
        config.target_location_id = Some("NYC".to_string());
        let version = match wire_version(&config.begin_string) {
            Ok(version) => version,
            Err(err) => panic!("test fixture uses an unsupported version: {err}"),
        };
        let factory = MessageFactory::new(&config, version);

        let frame = framed(factory.logon(1, 30, false));
        let raw = decode(&frame);
        // SenderLocationID (142) and TargetLocationID (143) are routing fields
        // of the standard header, so a configured value is stamped onto every
        // outbound message.
        assert_eq!(raw.get_field_str(142), Some("LON"));
        assert_eq!(raw.get_field_str(143), Some("NYC"));
    }

    #[test]
    fn test_header_omits_unset_location_ids() {
        let frame = framed(factory().logon(1, 30, false));
        let raw = decode(&frame);
        assert_eq!(raw.get_field_str(142), None);
        assert_eq!(raw.get_field_str(143), None);
    }

    #[test]
    fn test_wire_version_pre_fixt_passthrough() {
        assert_eq!(wire_version("FIX.4.4"), Ok(FixVersion::Fix44));
    }

    /// The mapping now lives once, in `ironfix_core::FixVersion`. This walks
    /// every version from that single list and asserts the engine frames each
    /// one exactly as the core table says — the cross-check that was
    /// impossible while the engine kept its own copy, since asserting against
    /// `ironfix-dictionary` would have taken a forbidden dependency.
    #[test]
    fn test_wire_version_matches_core_table_for_every_version() {
        for version in FixVersion::ALL {
            let resolved = wire_version(version.as_str());

            // Only a FIXT session with no application version is refused; it
            // cannot supply the required DefaultApplVerID (1137).
            if version.uses_fixt() && version.appl_ver_id().is_none() {
                match resolved {
                    Err(err) => assert_eq!(err.version, version.as_str()),
                    Ok(framable) => {
                        unreachable!("{version} must be refused, got {framable:?}")
                    }
                }
                continue;
            }

            assert_eq!(resolved, Ok(version));

            let frame = framed(factory_for(version.as_str()).logon(1, 30, false));
            let raw = decode(&frame);
            assert_eq!(
                raw.begin_string(),
                Ok(version.begin_string()),
                "{version} framed the wrong BeginString"
            );
            assert_eq!(
                raw.get_field_str(1137),
                version.appl_ver_id(),
                "{version} framed the wrong DefaultApplVerID"
            );
        }
    }

    #[test]
    fn test_wire_version_unknown_is_typed_error() {
        // An unsupported version must degrade to an explicit typed error, never
        // travel onto the wire as a fabricated BeginString.
        match wire_version("FIX.9.9") {
            Err(err) => assert_eq!(err.version, "FIX.9.9"),
            Ok(version) => panic!("FIX.9.9 must not be framed, got {version:?}"),
        }
    }

    #[test]
    fn test_wire_version_bare_fixt_is_rejected_for_missing_appl_ver_id() {
        // FIXT.1.1 names only the transport version. Its Logon requires
        // DefaultApplVerID (1137) and nothing here can supply it, so the
        // session is refused rather than sent without a required field.
        match wire_version("FIXT.1.1") {
            Err(err) => {
                assert_eq!(err.version, "FIXT.1.1");
                assert!(
                    err.detail.contains("1137"),
                    "the reason should name the missing field, got {}",
                    err.detail
                );
            }
            Ok(version) => panic!("bare FIXT.1.1 must be refused, got {version:?}"),
        }
    }

    #[test]
    fn test_wire_version_fix50_maps_to_fixt() {
        for (configured, appl_ver_id) in
            [("FIX.5.0", "7"), ("FIX.5.0SP1", "8"), ("FIX.5.0SP2", "9")]
        {
            match wire_version(configured) {
                Ok(version) => {
                    assert_eq!(version.begin_string(), "FIXT.1.1");
                    assert_eq!(version.appl_ver_id(), Some(appl_ver_id));
                }
                Err(err) => unreachable!("{configured} must be framable: {err}"),
            }
        }
    }

    #[test]
    fn test_fix50sp2_logon_carries_fixt_begin_string_and_default_appl_ver_id() {
        let frame = framed(factory_for("FIX.5.0SP2").logon(1, 30, false));
        let raw = decode(&frame);
        assert_eq!(raw.begin_string(), Ok("FIXT.1.1"));
        assert_eq!(raw.get_field_str(1137), Some("9"));
    }

    #[test]
    fn test_fix50sp2_application_message_carries_appl_ver_id() {
        let mut message = OutboundMessage::new(MsgType::NewOrderSingle);
        message.push_str(11, "ORDER-1");

        let frame = framed(factory_for("FIX.5.0SP2").application_message(2, &message));
        let raw = decode(&frame);
        assert_eq!(raw.begin_string(), Ok("FIXT.1.1"));
        assert_eq!(raw.get_field_str(1128), Some("9"));
    }

    #[test]
    fn test_peer_identity_accepts_reversed_comp_ids() {
        let identity = PeerIdentity::new(&config_for("FIX.4.4"));
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "0");
        encoder.put_str(49, "VENUE");
        encoder.put_str(56, "CLIENT");
        encoder.put_uint(34, 1);
        let frame = match encoder.finish() {
            Ok(frame) => frame.to_vec(),
            Err(err) => panic!("fixture frame must encode: {err}"),
        };

        assert_eq!(identity.validate(&decode(&frame)), Ok(()));
    }

    #[test]
    fn test_peer_identity_rejects_wrong_sender_comp_id() {
        let identity = PeerIdentity::new(&config_for("FIX.4.4"));
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "0");
        encoder.put_str(49, "OTHER");
        encoder.put_str(56, "CLIENT");
        encoder.put_uint(34, 1);
        let frame = match encoder.finish() {
            Ok(frame) => frame.to_vec(),
            Err(err) => panic!("fixture frame must encode: {err}"),
        };

        assert_eq!(
            identity.validate(&decode(&frame)),
            Err(IdentityMismatch {
                tag: 49,
                expected: "VENUE".to_string(),
                received: "OTHER".to_string(),
            })
        );
    }

    #[test]
    fn test_peer_identity_rejects_missing_sub_id_when_configured() {
        let config = config_for("FIX.4.4").with_sender_sub_id("DESK");
        let identity = PeerIdentity::new(&config);
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "0");
        encoder.put_str(49, "VENUE");
        encoder.put_str(56, "CLIENT");
        encoder.put_uint(34, 1);
        let frame = match encoder.finish() {
            Ok(frame) => frame.to_vec(),
            Err(err) => panic!("fixture frame must encode: {err}"),
        };

        // Our SenderSubID is the peer's TargetSubID (57).
        assert_eq!(
            identity.validate(&decode(&frame)),
            Err(IdentityMismatch {
                tag: 57,
                expected: "DESK".to_string(),
                received: String::new(),
            })
        );
    }
}
