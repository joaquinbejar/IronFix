/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! SBE encoding and decoding of the FIXP session messages, on `ironsbe-core`.
//!
//! The SBE primitives come from `ironsbe-core`: the 8-byte [`MessageHeader`]
//! (`blockLength`, `templateId`, `schemaId`, `version`), the `uint16`
//! [`VarDataHeader`] of the `Object` and `CharacterString` composites, and
//! the little-endian [`ReadBuffer`] / [`WriteBuffer`] accessors. None of those
//! types appears in this crate's public API, so a breaking `ironsbe-core`
//! release is not a breaking release of this crate.
//!
//! # Untrusted input
//!
//! `ironsbe-core`'s accessors index their buffer and panic past its end, so
//! this module checks every length before it reads: the header against the
//! input, the declared `blockLength` against the root block this schema
//! version reads ([`FixpDecodeError::BlockLengthTooShort`]) and against the
//! input ([`FixpDecodeError::Truncated`]), and every variable-length field's
//! declared length against the bytes actually present before any of them is
//! copied. A declared length of `0xFFFF`, the SBE `uint16` null value, is
//! refused ([`FixpDecodeError::NullVarDataLength`]). A copy is never larger
//! than the input, and never larger than 65 534 bytes.
//!
//! A `blockLength` larger than this version's root block is accepted and the
//! extra bytes skipped, as SBE schema evolution requires, and the `version`
//! field is not checked: schema version 0 is the only one published.
//!
//! # One message per call
//!
//! [`SessionMessage::decode`] decodes the message at the start of its input
//! and returns how many bytes it used. Whatever follows (on a datagram
//! transport, the application messages a Sequence precedes) is left to the
//! caller.
//!
//! That length counts the header, the root block as long as its declared
//! `blockLength` (extension fields included), and the variable-length fields
//! schema version 0 defines. A later schema version that appended
//! variable-length fields would make a message longer than this count: a
//! driver that reads several messages from one buffer relies on version 0,
//! or on framing that delimits each message (SOFH) instead.

use crate::error::{FixpDecodeError, FixpEncodeError};
use crate::messages::{
    Applied, Context, Establish, EstablishmentAck, EstablishmentReject, FinishedReceiving,
    FinishedSending, MessageTemplate, Negotiate, NegotiationReject, NegotiationResponse,
    NotApplied, Retransmission, RetransmitReject, RetransmitRequest, SCHEMA_ID, SCHEMA_VERSION,
    Sequence, SessionMessage, Terminate, Topic, UnsequencedHeartbeat,
};
use crate::types::{
    Credentials, EstablishmentRejectCode, FlowType, MAX_VAR_DATA_LEN, Nanotime,
    NegotiationRejectCode, RetransmitRejectCode, SessionId, TerminationCode,
};
use ironsbe_core::{MessageHeader, ReadBuffer, VarDataHeader, WriteBuffer};

/// Length of the SBE message header, in bytes.
const HEADER_LEN: usize = MessageHeader::ENCODED_LENGTH;

/// Length of the `uint16` prefix of a variable-length field, in bytes.
const VAR_PREFIX_LEN: usize = VarDataHeader::ENCODED_LENGTH;

/// The SBE null value of an optional `uint64` (`ordinal` or `nanotime`).
const NULL_U64: u64 = u64::MAX;

/// The variable-length fields of a message, in schema order: at most two,
/// each with its schema name.
type VarFields<'a> = [Option<(&'static str, &'a [u8])>; 2];

/// Returns `true` if `src` starts with an SBE header naming the FIXP session
/// schema.
///
/// A driver whose transport carries both FIXP session messages and
/// application messages of another SBE schema routes on this before decoding.
/// It reads the header only; the message may still be malformed.
#[must_use]
pub fn is_session_message(src: &[u8]) -> bool {
    if src.len() < HEADER_LEN {
        return false;
    }
    let header = MessageHeader::wrap(src, 0);
    let schema_id = header.schema_id;
    schema_id == SCHEMA_ID
}

impl SessionMessage {
    /// Decodes the FIXP session message at the start of `src`.
    ///
    /// Returns the message and the number of bytes it occupies as far as
    /// schema version 0 describes it: the header, the declared root block and
    /// the version-0 variable-length fields (see the module documentation).
    ///
    /// # Errors
    /// Returns a [`FixpDecodeError`] when `src` is not a complete, valid FIXP
    /// session message; see the module documentation.
    pub fn decode(src: &[u8]) -> Result<(Self, usize), FixpDecodeError> {
        if src.len() < HEADER_LEN {
            return Err(FixpDecodeError::Truncated {
                needed: HEADER_LEN,
                available: src.len(),
            });
        }
        let header = MessageHeader::wrap(src, 0);
        let schema_id = header.schema_id;
        if schema_id != SCHEMA_ID {
            return Err(FixpDecodeError::SchemaMismatch {
                schema_id,
                expected: SCHEMA_ID,
            });
        }
        let block_length = header.block_length;
        let template_id = header.template_id;
        match template_id {
            Negotiate::TEMPLATE_ID => decode_negotiate(src, block_length),
            NegotiationResponse::TEMPLATE_ID => decode_negotiation_response(src, block_length),
            NegotiationReject::TEMPLATE_ID => decode_negotiation_reject(src, block_length),
            Topic::TEMPLATE_ID => decode_topic(src, block_length),
            Establish::TEMPLATE_ID => decode_establish(src, block_length),
            EstablishmentAck::TEMPLATE_ID => decode_establishment_ack(src, block_length),
            EstablishmentReject::TEMPLATE_ID => decode_establishment_reject(src, block_length),
            Sequence::TEMPLATE_ID => decode_sequence(src, block_length),
            Context::TEMPLATE_ID => decode_context(src, block_length),
            UnsequencedHeartbeat::TEMPLATE_ID => decode_unsequenced_heartbeat(src, block_length),
            RetransmitRequest::TEMPLATE_ID => decode_retransmit_request(src, block_length),
            Retransmission::TEMPLATE_ID => decode_retransmission(src, block_length),
            RetransmitReject::TEMPLATE_ID => decode_retransmit_reject(src, block_length),
            Terminate::TEMPLATE_ID => decode_terminate(src, block_length),
            FinishedSending::TEMPLATE_ID => decode_finished_sending(src, block_length),
            FinishedReceiving::TEMPLATE_ID => decode_finished_receiving(src, block_length),
            Applied::TEMPLATE_ID => decode_applied(src, block_length),
            NotApplied::TEMPLATE_ID => decode_not_applied(src, block_length),
            MessageTemplate::TEMPLATE_ID => decode_message_template(src, block_length),
            other => Err(FixpDecodeError::UnknownTemplate { template_id: other }),
        }
    }

    /// Returns the encoded length of the message, header included, in bytes.
    ///
    /// # Errors
    /// Returns [`FixpEncodeError::VarDataTooLong`] if a variable-length field
    /// exceeds its 16-bit length prefix.
    pub fn encoded_len(&self) -> Result<usize, FixpEncodeError> {
        // At most 8 + 65 535 + 2 * (2 + 65 534) bytes: no sum below can
        // overflow, because each field length is checked first.
        let (block, var_fields) = self.layout();
        let mut len = HEADER_LEN + usize::from(block);
        for (field, bytes) in var_fields.into_iter().flatten() {
            if bytes.len() > MAX_VAR_DATA_LEN {
                return Err(FixpEncodeError::VarDataTooLong {
                    field,
                    len: bytes.len(),
                    max: MAX_VAR_DATA_LEN,
                });
            }
            len += VAR_PREFIX_LEN + bytes.len();
        }
        Ok(len)
    }

    /// Encodes the message at the start of `dst` and returns its length.
    ///
    /// Nothing is written unless the whole message fits.
    ///
    /// # Errors
    /// Returns [`FixpEncodeError::VarDataTooLong`] for a variable-length field
    /// above its length prefix, or [`FixpEncodeError::BufferTooSmall`] if
    /// `dst` cannot hold the message.
    pub fn encode_into(&self, dst: &mut [u8]) -> Result<usize, FixpEncodeError> {
        let len = self.encoded_len()?;
        let available = dst.len();
        let Some(buf) = dst.get_mut(..len) else {
            return Err(FixpEncodeError::BufferTooSmall {
                needed: len,
                available,
            });
        };
        self.write(buf)?;
        Ok(len)
    }

    /// Appends the encoded message to `dst` and returns its length.
    ///
    /// # Errors
    /// Returns [`FixpEncodeError::VarDataTooLong`] for a variable-length field
    /// above its length prefix, or [`FixpEncodeError::CapacityOverflow`] if
    /// `dst` cannot grow by the encoded length; `dst` is left unchanged.
    pub fn encode(&self, dst: &mut Vec<u8>) -> Result<usize, FixpEncodeError> {
        let len = self.encoded_len()?;
        let start = dst.len();
        let end = start
            .checked_add(len)
            .ok_or(FixpEncodeError::CapacityOverflow { needed: len })?;
        dst.try_reserve(len)
            .map_err(|_| FixpEncodeError::CapacityOverflow { needed: len })?;
        dst.resize(end, 0);
        let written = match dst.get_mut(start..) {
            Some(buf) => self.write(buf),
            None => Ok(()),
        };
        if let Err(error) = written {
            dst.truncate(start);
            return Err(error);
        }
        Ok(len)
    }

    /// The root block length and the variable-length fields, in schema order.
    fn layout(&self) -> (u16, VarFields<'_>) {
        match self {
            Self::Negotiate(m) => (
                Negotiate::BLOCK_LENGTH,
                [
                    Some(("Credentials", credentials_bytes(&m.credentials))),
                    None,
                ],
            ),
            Self::NegotiationResponse(m) => (
                NegotiationResponse::BLOCK_LENGTH,
                [
                    Some(("Credentials", credentials_bytes(&m.credentials))),
                    None,
                ],
            ),
            Self::NegotiationReject(m) => (
                NegotiationReject::BLOCK_LENGTH,
                [Some(("Reason", m.reason.as_bytes())), None],
            ),
            Self::Topic(m) => (
                Topic::BLOCK_LENGTH,
                [Some(("Classification", m.classification.as_slice())), None],
            ),
            Self::Establish(m) => (
                Establish::BLOCK_LENGTH,
                [
                    Some(("Credentials", credentials_bytes(&m.credentials))),
                    None,
                ],
            ),
            Self::EstablishmentAck(_) => (EstablishmentAck::BLOCK_LENGTH, [None, None]),
            Self::EstablishmentReject(m) => (
                EstablishmentReject::BLOCK_LENGTH,
                [Some(("Reason", m.reason.as_bytes())), None],
            ),
            Self::Sequence(_) => (Sequence::BLOCK_LENGTH, [None, None]),
            Self::Context(_) => (Context::BLOCK_LENGTH, [None, None]),
            Self::UnsequencedHeartbeat(_) => (UnsequencedHeartbeat::BLOCK_LENGTH, [None, None]),
            Self::RetransmitRequest(_) => (RetransmitRequest::BLOCK_LENGTH, [None, None]),
            Self::Retransmission(_) => (Retransmission::BLOCK_LENGTH, [None, None]),
            Self::RetransmitReject(m) => (
                RetransmitReject::BLOCK_LENGTH,
                [Some(("Reason", m.reason.as_bytes())), None],
            ),
            Self::Terminate(m) => (
                Terminate::BLOCK_LENGTH,
                [Some(("Reason", m.reason.as_bytes())), None],
            ),
            Self::FinishedSending(_) => (FinishedSending::BLOCK_LENGTH, [None, None]),
            Self::FinishedReceiving(_) => (FinishedReceiving::BLOCK_LENGTH, [None, None]),
            Self::Applied(_) => (Applied::BLOCK_LENGTH, [None, None]),
            Self::NotApplied(_) => (NotApplied::BLOCK_LENGTH, [None, None]),
            Self::MessageTemplate(m) => (
                MessageTemplate::BLOCK_LENGTH,
                [
                    Some(("Version", m.version.as_slice())),
                    Some(("Template", m.template.as_slice())),
                ],
            ),
        }
    }

    /// Writes the message into `buf`, which is exactly
    /// [`encoded_len`](Self::encoded_len) bytes long.
    fn write(&self, buf: &mut [u8]) -> Result<(), FixpEncodeError> {
        let (block, var_fields) = self.layout();
        MessageHeader::new(block, self.template_id(), SCHEMA_ID, SCHEMA_VERSION).encode(buf, 0);
        let mut out = BlockWriter { buf };
        match self {
            Self::Negotiate(m) => {
                out.session_id(0, m.session_id);
                out.u64(16, m.timestamp.as_nanos());
                out.u8(24, m.client_flow.as_u8());
            }
            Self::NegotiationResponse(m) => {
                out.session_id(0, m.session_id);
                out.u64(16, m.request_timestamp.as_nanos());
                out.u8(24, m.server_flow.as_u8());
            }
            Self::NegotiationReject(m) => {
                out.session_id(0, m.session_id);
                out.u64(16, m.request_timestamp.as_nanos());
                out.u8(24, m.code.as_u8());
            }
            Self::Topic(m) => {
                out.session_id(0, m.session_id);
                out.u8(16, m.flow.as_u8());
                out.u32(17, m.keepalive_interval);
            }
            Self::Establish(m) => {
                out.session_id(0, m.session_id);
                out.u64(16, m.timestamp.as_nanos());
                out.u32(24, m.keepalive_interval);
                out.u64(28, m.next_seq_no.unwrap_or(NULL_U64));
            }
            Self::EstablishmentAck(m) => {
                out.session_id(0, m.session_id);
                out.u64(16, m.request_timestamp.as_nanos());
                out.u32(24, m.keepalive_interval);
                out.u64(28, m.next_seq_no.unwrap_or(NULL_U64));
            }
            Self::EstablishmentReject(m) => {
                out.session_id(0, m.session_id);
                out.u64(16, m.request_timestamp.as_nanos());
                out.u8(24, m.code.as_u8());
            }
            Self::Sequence(m) => out.u64(0, m.next_seq_no),
            Self::Context(m) => {
                out.session_id(0, m.session_id);
                out.u64(16, m.next_seq_no);
            }
            Self::UnsequencedHeartbeat(_) => {}
            Self::RetransmitRequest(m) => {
                out.session_id(0, m.session_id);
                out.u64(16, m.timestamp.as_nanos());
                out.u64(24, m.from_seq_no);
                out.u32(32, m.count);
            }
            Self::Retransmission(m) => {
                out.session_id(0, m.session_id);
                out.u64(16, m.request_timestamp.as_nanos());
                out.u64(24, m.next_seq_no);
                out.u32(32, m.count);
            }
            Self::RetransmitReject(m) => {
                out.session_id(0, m.session_id);
                out.u64(16, m.request_timestamp.as_nanos());
                out.u8(24, m.code.as_u8());
            }
            Self::Terminate(m) => {
                out.session_id(0, m.session_id);
                out.u8(16, m.code.as_u8());
            }
            Self::FinishedSending(m) => {
                out.session_id(0, m.session_id);
                out.u64(16, m.last_seq_no.unwrap_or(NULL_U64));
            }
            Self::FinishedReceiving(m) => out.session_id(0, m.session_id),
            Self::Applied(m) => {
                out.u64(0, m.from_seq_no);
                out.u32(8, m.count);
            }
            Self::NotApplied(m) => {
                out.u64(0, m.from_seq_no);
                out.u32(8, m.count);
            }
            Self::MessageTemplate(m) => {
                out.u32(0, m.encoding_type);
                out.u64(4, m.effective_time.map_or(NULL_U64, Nanotime::as_nanos));
            }
        }
        // Offsets below stay within `buf`, which is `encoded_len` bytes long,
        // so they are at most 8 + 65 535 + 2 * (2 + 65 534) and cannot
        // overflow; `ironsbe-core`'s writers index `buf` at them.
        let mut position = HEADER_LEN + usize::from(block);
        for (field, bytes) in var_fields.into_iter().flatten() {
            let len = u16::try_from(bytes.len())
                .ok()
                .filter(|_| bytes.len() <= MAX_VAR_DATA_LEN)
                .ok_or(FixpEncodeError::VarDataTooLong {
                    field,
                    len: bytes.len(),
                    max: MAX_VAR_DATA_LEN,
                })?;
            VarDataHeader::new(len).encode(out.buf, position);
            out.buf.put_bytes(position + VAR_PREFIX_LEN, bytes);
            position += VAR_PREFIX_LEN + bytes.len();
        }
        Ok(())
    }
}

/// Writes root-block fields at offsets relative to the end of the header.
///
/// The buffer is exactly the encoded length of the message, so every offset
/// below its root block length is in bounds.
struct BlockWriter<'a> {
    buf: &'a mut [u8],
}

impl BlockWriter<'_> {
    fn session_id(&mut self, offset: usize, value: SessionId) {
        self.buf.put_bytes(HEADER_LEN + offset, value.as_bytes());
    }

    fn u64(&mut self, offset: usize, value: u64) {
        self.buf.put_u64_le(HEADER_LEN + offset, value);
    }

    fn u32(&mut self, offset: usize, value: u32) {
        self.buf.put_u32_le(HEADER_LEN + offset, value);
    }

    fn u8(&mut self, offset: usize, value: u8) {
        self.buf.put_u8(HEADER_LEN + offset, value);
    }
}

/// The wire bytes of an optional credentials field: absent is zero-length.
fn credentials_bytes(credentials: &Option<Credentials>) -> &[u8] {
    credentials.as_ref().map_or(&[], Credentials::expose)
}

/// Reads one message: its root block and then its variable-length fields.
struct Reader<'a> {
    src: &'a [u8],
    /// The root block, exactly as long as this schema version's block.
    block: &'a [u8],
    /// Offset in `src` of the next variable-length field.
    position: usize,
}

impl<'a> Reader<'a> {
    /// Checks the declared `blockLength` and slices the root block.
    fn open(
        src: &'a [u8],
        block_length: u16,
        message: &'static str,
        minimum: u16,
    ) -> Result<Self, FixpDecodeError> {
        if block_length < minimum {
            return Err(FixpDecodeError::BlockLengthTooShort {
                message,
                block_length,
                minimum,
            });
        }
        let end = HEADER_LEN + usize::from(block_length);
        if src.len() < end {
            return Err(FixpDecodeError::Truncated {
                needed: end,
                available: src.len(),
            });
        }
        let block = src
            .get(HEADER_LEN..HEADER_LEN + usize::from(minimum))
            .ok_or(FixpDecodeError::Truncated {
                needed: end,
                available: src.len(),
            })?;
        Ok(Self {
            src,
            block,
            position: end,
        })
    }

    fn session_id(&self, offset: usize) -> SessionId {
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(self.block.get_bytes(offset, 16));
        SessionId::from_bytes(bytes)
    }

    fn u64(&self, offset: usize) -> u64 {
        self.block.get_u64_le(offset)
    }

    fn optional_u64(&self, offset: usize) -> Option<u64> {
        match self.block.get_u64_le(offset) {
            NULL_U64 => None,
            value => Some(value),
        }
    }

    fn nanotime(&self, offset: usize) -> Nanotime {
        Nanotime::from_nanos(self.u64(offset))
    }

    fn u32(&self, offset: usize) -> u32 {
        self.block.get_u32_le(offset)
    }

    fn u8(&self, offset: usize) -> u8 {
        self.block.get_u8(offset)
    }

    fn flow(&self, offset: usize, field: &'static str) -> Result<FlowType, FixpDecodeError> {
        let value = self.u8(offset);
        FlowType::from_u8(value).ok_or(FixpDecodeError::InvalidEnumValue { field, value })
    }

    /// Reads the next variable-length field, checking its declared length
    /// against the bytes present before slicing.
    fn var_data(&mut self) -> Result<&'a [u8], FixpDecodeError> {
        let available = self.src.len();
        let prefix_end =
            self.position
                .checked_add(VAR_PREFIX_LEN)
                .ok_or(FixpDecodeError::Truncated {
                    needed: usize::MAX,
                    available,
                })?;
        if available < prefix_end {
            return Err(FixpDecodeError::Truncated {
                needed: prefix_end,
                available,
            });
        }
        let prefix = VarDataHeader::wrap(self.src, self.position);
        let len = prefix.length;
        if len == u16::MAX {
            return Err(FixpDecodeError::NullVarDataLength {
                offset: self.position,
            });
        }
        let end = prefix_end
            .checked_add(usize::from(len))
            .ok_or(FixpDecodeError::Truncated {
                needed: usize::MAX,
                available,
            })?;
        let bytes = self
            .src
            .get(prefix_end..end)
            .ok_or(FixpDecodeError::Truncated {
                needed: end,
                available: self.src.len(),
            })?;
        self.position = end;
        Ok(bytes)
    }

    fn credentials(&mut self) -> Result<Option<Credentials>, FixpDecodeError> {
        let bytes = self.var_data()?;
        if bytes.is_empty() {
            return Ok(None);
        }
        Ok(Some(Credentials::from_wire(bytes.to_vec())))
    }

    fn text(&mut self, field: &'static str) -> Result<String, FixpDecodeError> {
        let bytes = self.var_data()?;
        let text =
            std::str::from_utf8(bytes).map_err(|_| FixpDecodeError::InvalidUtf8 { field })?;
        Ok(text.to_owned())
    }

    fn finish(self, message: SessionMessage) -> (SessionMessage, usize) {
        (message, self.position)
    }
}

fn decode_negotiate(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let mut r = Reader::open(src, block_length, Negotiate::NAME, Negotiate::BLOCK_LENGTH)?;
    let session_id = r.session_id(0);
    let timestamp = r.nanotime(16);
    let client_flow = r.flow(24, "ClientFlow")?;
    let credentials = r.credentials()?;
    Ok(r.finish(SessionMessage::Negotiate(Negotiate {
        session_id,
        timestamp,
        client_flow,
        credentials,
    })))
}

fn decode_negotiation_response(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let mut r = Reader::open(
        src,
        block_length,
        NegotiationResponse::NAME,
        NegotiationResponse::BLOCK_LENGTH,
    )?;
    let session_id = r.session_id(0);
    let request_timestamp = r.nanotime(16);
    let server_flow = r.flow(24, "ServerFlow")?;
    let credentials = r.credentials()?;
    Ok(
        r.finish(SessionMessage::NegotiationResponse(NegotiationResponse {
            session_id,
            request_timestamp,
            server_flow,
            credentials,
        })),
    )
}

fn decode_negotiation_reject(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let mut r = Reader::open(
        src,
        block_length,
        NegotiationReject::NAME,
        NegotiationReject::BLOCK_LENGTH,
    )?;
    let session_id = r.session_id(0);
    let request_timestamp = r.nanotime(16);
    let value = r.u8(24);
    let code = NegotiationRejectCode::from_u8(value).ok_or(FixpDecodeError::InvalidEnumValue {
        field: "NegotiationRejectCode",
        value,
    })?;
    let reason = r.text("Reason")?;
    Ok(
        r.finish(SessionMessage::NegotiationReject(NegotiationReject {
            session_id,
            request_timestamp,
            code,
            reason,
        })),
    )
}

fn decode_topic(src: &[u8], block_length: u16) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let mut r = Reader::open(src, block_length, Topic::NAME, Topic::BLOCK_LENGTH)?;
    let session_id = r.session_id(0);
    let flow = r.flow(16, "Flow")?;
    let keepalive_interval = r.u32(17);
    let classification = r.var_data()?.to_vec();
    Ok(r.finish(SessionMessage::Topic(Topic {
        session_id,
        flow,
        keepalive_interval,
        classification,
    })))
}

fn decode_establish(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let mut r = Reader::open(src, block_length, Establish::NAME, Establish::BLOCK_LENGTH)?;
    let session_id = r.session_id(0);
    let timestamp = r.nanotime(16);
    let keepalive_interval = r.u32(24);
    let next_seq_no = r.optional_u64(28);
    let credentials = r.credentials()?;
    Ok(r.finish(SessionMessage::Establish(Establish {
        session_id,
        timestamp,
        keepalive_interval,
        next_seq_no,
        credentials,
    })))
}

fn decode_establishment_ack(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let r = Reader::open(
        src,
        block_length,
        EstablishmentAck::NAME,
        EstablishmentAck::BLOCK_LENGTH,
    )?;
    let message = SessionMessage::EstablishmentAck(EstablishmentAck {
        session_id: r.session_id(0),
        request_timestamp: r.nanotime(16),
        keepalive_interval: r.u32(24),
        next_seq_no: r.optional_u64(28),
    });
    Ok(r.finish(message))
}

fn decode_establishment_reject(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let mut r = Reader::open(
        src,
        block_length,
        EstablishmentReject::NAME,
        EstablishmentReject::BLOCK_LENGTH,
    )?;
    let session_id = r.session_id(0);
    let request_timestamp = r.nanotime(16);
    let value = r.u8(24);
    let code =
        EstablishmentRejectCode::from_u8(value).ok_or(FixpDecodeError::InvalidEnumValue {
            field: "EstablishmentRejectCode",
            value,
        })?;
    let reason = r.text("Reason")?;
    Ok(
        r.finish(SessionMessage::EstablishmentReject(EstablishmentReject {
            session_id,
            request_timestamp,
            code,
            reason,
        })),
    )
}

fn decode_sequence(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let r = Reader::open(src, block_length, Sequence::NAME, Sequence::BLOCK_LENGTH)?;
    let message = SessionMessage::Sequence(Sequence {
        next_seq_no: r.u64(0),
    });
    Ok(r.finish(message))
}

fn decode_context(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let r = Reader::open(src, block_length, Context::NAME, Context::BLOCK_LENGTH)?;
    let message = SessionMessage::Context(Context {
        session_id: r.session_id(0),
        next_seq_no: r.u64(16),
    });
    Ok(r.finish(message))
}

fn decode_unsequenced_heartbeat(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let r = Reader::open(
        src,
        block_length,
        UnsequencedHeartbeat::NAME,
        UnsequencedHeartbeat::BLOCK_LENGTH,
    )?;
    Ok(r.finish(SessionMessage::UnsequencedHeartbeat(UnsequencedHeartbeat)))
}

fn decode_retransmit_request(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let r = Reader::open(
        src,
        block_length,
        RetransmitRequest::NAME,
        RetransmitRequest::BLOCK_LENGTH,
    )?;
    let message = SessionMessage::RetransmitRequest(RetransmitRequest {
        session_id: r.session_id(0),
        timestamp: r.nanotime(16),
        from_seq_no: r.u64(24),
        count: r.u32(32),
    });
    Ok(r.finish(message))
}

fn decode_retransmission(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let r = Reader::open(
        src,
        block_length,
        Retransmission::NAME,
        Retransmission::BLOCK_LENGTH,
    )?;
    let message = SessionMessage::Retransmission(Retransmission {
        session_id: r.session_id(0),
        request_timestamp: r.nanotime(16),
        next_seq_no: r.u64(24),
        count: r.u32(32),
    });
    Ok(r.finish(message))
}

fn decode_retransmit_reject(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let mut r = Reader::open(
        src,
        block_length,
        RetransmitReject::NAME,
        RetransmitReject::BLOCK_LENGTH,
    )?;
    let session_id = r.session_id(0);
    let request_timestamp = r.nanotime(16);
    let value = r.u8(24);
    let code = RetransmitRejectCode::from_u8(value).ok_or(FixpDecodeError::InvalidEnumValue {
        field: "RetransmitRejectCode",
        value,
    })?;
    let reason = r.text("Reason")?;
    Ok(r.finish(SessionMessage::RetransmitReject(RetransmitReject {
        session_id,
        request_timestamp,
        code,
        reason,
    })))
}

fn decode_terminate(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let mut r = Reader::open(src, block_length, Terminate::NAME, Terminate::BLOCK_LENGTH)?;
    let session_id = r.session_id(0);
    let value = r.u8(16);
    let code = TerminationCode::from_u8(value).ok_or(FixpDecodeError::InvalidEnumValue {
        field: "TerminationCode",
        value,
    })?;
    let reason = r.text("Reason")?;
    Ok(r.finish(SessionMessage::Terminate(Terminate {
        session_id,
        code,
        reason,
    })))
}

fn decode_finished_sending(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let r = Reader::open(
        src,
        block_length,
        FinishedSending::NAME,
        FinishedSending::BLOCK_LENGTH,
    )?;
    let message = SessionMessage::FinishedSending(FinishedSending {
        session_id: r.session_id(0),
        last_seq_no: r.optional_u64(16),
    });
    Ok(r.finish(message))
}

fn decode_finished_receiving(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let r = Reader::open(
        src,
        block_length,
        FinishedReceiving::NAME,
        FinishedReceiving::BLOCK_LENGTH,
    )?;
    let message = SessionMessage::FinishedReceiving(FinishedReceiving {
        session_id: r.session_id(0),
    });
    Ok(r.finish(message))
}

fn decode_applied(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let r = Reader::open(src, block_length, Applied::NAME, Applied::BLOCK_LENGTH)?;
    let message = SessionMessage::Applied(Applied {
        from_seq_no: r.u64(0),
        count: r.u32(8),
    });
    Ok(r.finish(message))
}

fn decode_not_applied(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let r = Reader::open(
        src,
        block_length,
        NotApplied::NAME,
        NotApplied::BLOCK_LENGTH,
    )?;
    let message = SessionMessage::NotApplied(NotApplied {
        from_seq_no: r.u64(0),
        count: r.u32(8),
    });
    Ok(r.finish(message))
}

fn decode_message_template(
    src: &[u8],
    block_length: u16,
) -> Result<(SessionMessage, usize), FixpDecodeError> {
    let mut r = Reader::open(
        src,
        block_length,
        MessageTemplate::NAME,
        MessageTemplate::BLOCK_LENGTH,
    )?;
    let encoding_type = r.u32(0);
    let effective_time = r.optional_u64(4).map(Nanotime::from_nanos);
    let version = r.var_data()?.to_vec();
    let template = r.var_data()?.to_vec();
    Ok(r.finish(SessionMessage::MessageTemplate(MessageTemplate {
        encoding_type,
        effective_time,
        version,
        template,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> SessionId {
        SessionId::from_bytes([byte; 16])
    }

    fn credentials(bytes: &[u8]) -> Option<Credentials> {
        Credentials::try_new(bytes.to_vec()).ok()
    }

    /// One sample of every message, with every optional field populated.
    fn samples() -> Vec<SessionMessage> {
        vec![
            SessionMessage::Negotiate(Negotiate {
                session_id: id(1),
                timestamp: Nanotime::from_nanos(1_700_000_000_000_000_001),
                client_flow: FlowType::Idempotent,
                credentials: credentials(b"user:secret"),
            }),
            SessionMessage::NegotiationResponse(NegotiationResponse {
                session_id: id(2),
                request_timestamp: Nanotime::from_nanos(42),
                server_flow: FlowType::Recoverable,
                credentials: credentials(b"server-id"),
            }),
            SessionMessage::NegotiationReject(NegotiationReject {
                session_id: id(3),
                request_timestamp: Nanotime::from_nanos(43),
                code: NegotiationRejectCode::DuplicateId,
                reason: "duplicate session id".to_owned(),
            }),
            SessionMessage::Topic(Topic {
                session_id: id(4),
                flow: FlowType::Idempotent,
                keepalive_interval: 1_000,
                classification: b"XNAS".to_vec(),
            }),
            SessionMessage::Establish(Establish {
                session_id: id(5),
                timestamp: Nanotime::from_nanos(44),
                keepalive_interval: 5_000,
                next_seq_no: Some(17),
                credentials: credentials(b"token"),
            }),
            SessionMessage::EstablishmentAck(EstablishmentAck {
                session_id: id(6),
                request_timestamp: Nanotime::from_nanos(45),
                keepalive_interval: 10_000,
                next_seq_no: Some(1_000),
            }),
            SessionMessage::EstablishmentReject(EstablishmentReject {
                session_id: id(7),
                request_timestamp: Nanotime::from_nanos(46),
                code: EstablishmentRejectCode::KeepaliveInterval,
                reason: "keepalive out of range".to_owned(),
            }),
            SessionMessage::Sequence(Sequence { next_seq_no: 99 }),
            SessionMessage::Context(Context {
                session_id: id(9),
                next_seq_no: 100,
            }),
            SessionMessage::UnsequencedHeartbeat(UnsequencedHeartbeat),
            SessionMessage::RetransmitRequest(RetransmitRequest {
                session_id: id(11),
                timestamp: Nanotime::from_nanos(47),
                from_seq_no: 1_000,
                count: 100,
            }),
            SessionMessage::Retransmission(Retransmission {
                session_id: id(12),
                request_timestamp: Nanotime::from_nanos(47),
                next_seq_no: 1_000,
                count: 50,
            }),
            SessionMessage::RetransmitReject(RetransmitReject {
                session_id: id(13),
                request_timestamp: Nanotime::from_nanos(48),
                code: RetransmitRejectCode::RequestLimitExceeded,
                reason: "count exceeds 500".to_owned(),
            }),
            SessionMessage::Terminate(Terminate {
                session_id: id(14),
                code: TerminationCode::ReRequestInProgress,
                reason: "retransmission in progress".to_owned(),
            }),
            SessionMessage::FinishedSending(FinishedSending {
                session_id: id(15),
                last_seq_no: Some(201),
            }),
            SessionMessage::FinishedReceiving(FinishedReceiving { session_id: id(16) }),
            SessionMessage::Applied(Applied {
                from_seq_no: 10,
                count: 3,
            }),
            SessionMessage::NotApplied(NotApplied {
                from_seq_no: 101,
                count: 100,
            }),
            SessionMessage::MessageTemplate(MessageTemplate {
                encoding_type: 0x5BE0,
                effective_time: Some(Nanotime::from_nanos(49)),
                version: b"1.0".to_vec(),
                template: b"<messageSchema/>".to_vec(),
            }),
        ]
    }

    fn encode(message: &SessionMessage) -> Vec<u8> {
        let mut wire = Vec::new();
        let encoded = message.encode(&mut wire);
        assert!(encoded.is_ok(), "{} failed to encode", message.name());
        wire
    }

    #[test]
    fn test_every_session_message_round_trips() {
        for message in samples() {
            let wire = encode(&message);
            assert_eq!(message.encoded_len(), Ok(wire.len()));
            assert!(is_session_message(&wire));
            match SessionMessage::decode(&wire) {
                Ok((decoded, used)) => {
                    assert_eq!(decoded, message, "{} did not round trip", message.name());
                    assert_eq!(used, wire.len());
                }
                Err(error) => panic!("{} failed to decode: {error}", message.name()),
            }
        }
    }

    #[test]
    fn test_optional_fields_round_trip_as_absent() {
        let messages = [
            SessionMessage::Negotiate(Negotiate {
                session_id: id(1),
                timestamp: Nanotime::from_nanos(1),
                client_flow: FlowType::None,
                credentials: None,
            }),
            SessionMessage::Establish(Establish {
                session_id: id(1),
                timestamp: Nanotime::from_nanos(2),
                keepalive_interval: 1,
                next_seq_no: None,
                credentials: None,
            }),
            SessionMessage::EstablishmentAck(EstablishmentAck {
                session_id: id(1),
                request_timestamp: Nanotime::from_nanos(2),
                keepalive_interval: 1,
                next_seq_no: None,
            }),
            SessionMessage::FinishedSending(FinishedSending {
                session_id: id(1),
                last_seq_no: None,
            }),
            SessionMessage::MessageTemplate(MessageTemplate {
                encoding_type: 1,
                effective_time: None,
                version: Vec::new(),
                template: b"t".to_vec(),
            }),
            SessionMessage::Terminate(Terminate {
                session_id: id(1),
                code: TerminationCode::Finished,
                reason: String::new(),
            }),
        ];
        for message in messages {
            let wire = encode(&message);
            assert_eq!(
                SessionMessage::decode(&wire).map(|(m, _)| m),
                Ok(message.clone())
            );
        }
    }

    #[test]
    fn test_empty_credentials_encode_as_absent() {
        let message = SessionMessage::Negotiate(Negotiate {
            session_id: id(1),
            timestamp: Nanotime::from_nanos(1),
            client_flow: FlowType::Recoverable,
            credentials: credentials(b""),
        });
        let wire = encode(&message);
        match SessionMessage::decode(&wire) {
            Ok((SessionMessage::Negotiate(decoded), _)) => assert_eq!(decoded.credentials, None),
            other => panic!("unexpected decode result {other:?}"),
        }
    }

    #[test]
    fn test_sequence_wire_bytes_match_the_sbe_layout() {
        let wire = encode(&SessionMessage::Sequence(Sequence {
            next_seq_no: 0x0102_0304_0506_0708,
        }));
        // blockLength 8, templateId 8, schemaId 2748 (0x0ABC), version 0,
        // then NextSeqNo little-endian.
        assert_eq!(
            wire,
            vec![
                8, 0, 8, 0, 0xBC, 0x0A, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
            ]
        );
    }

    #[test]
    fn test_terminate_wire_bytes_place_the_reason_after_the_block() {
        let wire = encode(&SessionMessage::Terminate(Terminate {
            session_id: id(0xAA),
            code: TerminationCode::UnspecifiedError,
            reason: "x".to_owned(),
        }));
        assert_eq!(wire.len(), 8 + 17 + 2 + 1);
        assert_eq!(wire.get(..8), Some(&[17, 0, 14, 0, 0xBC, 0x0A, 0, 0][..]));
        assert_eq!(wire.get(8..24), Some(&[0xAA; 16][..]));
        assert_eq!(wire.get(24), Some(&1));
        assert_eq!(wire.get(25..), Some(&[1, 0, b'x'][..]));
    }

    #[test]
    fn test_decode_leaves_trailing_bytes_to_the_caller() {
        let mut wire = encode(&SessionMessage::Sequence(Sequence { next_seq_no: 5 }));
        wire.extend_from_slice(b"application message");
        match SessionMessage::decode(&wire) {
            Ok((SessionMessage::Sequence(sequence), used)) => {
                assert_eq!(sequence.next_seq_no, 5);
                assert_eq!(used, 16);
            }
            other => panic!("unexpected decode result {other:?}"),
        }
    }

    #[test]
    fn test_decode_skips_a_longer_block_from_a_newer_schema_version() {
        let mut wire = encode(&SessionMessage::Terminate(Terminate {
            session_id: id(1),
            code: TerminationCode::Finished,
            reason: "bye".to_owned(),
        }));
        // Grow the block by 3 bytes and set version 1, as an extension would.
        wire.splice(8 + 17..8 + 17, [0xEE, 0xEE, 0xEE]);
        if let Some(block_length) = wire.get_mut(0) {
            *block_length = 20;
        }
        if let Some(version) = wire.get_mut(6) {
            *version = 1;
        }
        match SessionMessage::decode(&wire) {
            Ok((SessionMessage::Terminate(terminate), used)) => {
                assert_eq!(terminate.reason, "bye");
                assert_eq!(used, wire.len());
            }
            other => panic!("unexpected decode result {other:?}"),
        }
    }

    #[test]
    fn test_decode_rejects_a_truncated_header() {
        for len in 0..HEADER_LEN {
            let wire = vec![0_u8; len];
            assert_eq!(
                SessionMessage::decode(&wire),
                Err(FixpDecodeError::Truncated {
                    needed: HEADER_LEN,
                    available: len,
                })
            );
            assert!(!is_session_message(&wire));
        }
    }

    #[test]
    fn test_decode_rejects_every_truncation_of_every_message() {
        for message in samples() {
            let wire = encode(&message);
            for len in 0..wire.len() {
                let truncated = wire.get(..len).unwrap_or(&[]);
                assert!(
                    matches!(
                        SessionMessage::decode(truncated),
                        Err(FixpDecodeError::Truncated { .. })
                    ),
                    "{} truncated to {len} bytes was not refused",
                    message.name()
                );
            }
        }
    }

    #[test]
    fn test_decode_rejects_another_schema() {
        let mut wire = encode(&SessionMessage::Sequence(Sequence { next_seq_no: 1 }));
        if let Some(schema) = wire.get_mut(4) {
            *schema = 0x01;
        }
        assert!(!is_session_message(&wire));
        assert!(matches!(
            SessionMessage::decode(&wire),
            Err(FixpDecodeError::SchemaMismatch {
                expected: SCHEMA_ID,
                ..
            })
        ));
    }

    #[test]
    fn test_decode_rejects_an_unknown_template() {
        for template in [0_u8, 20, 255] {
            let mut wire = encode(&SessionMessage::Sequence(Sequence { next_seq_no: 1 }));
            if let Some(slot) = wire.get_mut(2) {
                *slot = template;
            }
            assert_eq!(
                SessionMessage::decode(&wire),
                Err(FixpDecodeError::UnknownTemplate {
                    template_id: u16::from(template)
                })
            );
        }
    }

    #[test]
    fn test_decode_rejects_a_block_shorter_than_the_schema_block() {
        let mut wire = encode(&SessionMessage::RetransmitRequest(RetransmitRequest {
            session_id: id(1),
            timestamp: Nanotime::from_nanos(1),
            from_seq_no: 1,
            count: 1,
        }));
        if let Some(block_length) = wire.get_mut(0) {
            *block_length = 35;
        }
        assert_eq!(
            SessionMessage::decode(&wire),
            Err(FixpDecodeError::BlockLengthTooShort {
                message: "RetransmitRequest",
                block_length: 35,
                minimum: 36,
            })
        );
    }

    #[test]
    fn test_decode_rejects_a_block_length_beyond_the_input() {
        let mut wire = encode(&SessionMessage::Sequence(Sequence { next_seq_no: 1 }));
        if let Some(block_length) = wire.get_mut(1) {
            *block_length = 0xFF;
        }
        assert!(matches!(
            SessionMessage::decode(&wire),
            Err(FixpDecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn test_decode_rejects_a_var_data_length_beyond_the_input() {
        let mut wire = encode(&SessionMessage::Terminate(Terminate {
            session_id: id(1),
            code: TerminationCode::Finished,
            reason: "ok".to_owned(),
        }));
        // Declare a 65 534-byte reason with only 2 bytes behind it.
        if let Some(prefix) = wire.get_mut(25..27) {
            prefix.copy_from_slice(&[0xFE, 0xFF]);
        }
        assert_eq!(
            SessionMessage::decode(&wire),
            Err(FixpDecodeError::Truncated {
                needed: 27 + 65_534,
                available: 29,
            })
        );
    }

    #[test]
    fn test_decode_rejects_the_uint16_null_var_data_length() {
        let mut wire = encode(&SessionMessage::Terminate(Terminate {
            session_id: id(1),
            code: TerminationCode::Finished,
            reason: "ok".to_owned(),
        }));
        // 0xFFFF is the SBE uint16 null value, never a valid Length.
        if let Some(prefix) = wire.get_mut(25..27) {
            prefix.copy_from_slice(&[0xFF, 0xFF]);
        }
        wire.resize(27 + 65_535, b'r');
        assert_eq!(
            SessionMessage::decode(&wire),
            Err(FixpDecodeError::NullVarDataLength { offset: 25 })
        );
    }

    #[test]
    fn test_var_data_of_65_534_bytes_round_trips() {
        let message = SessionMessage::Terminate(Terminate {
            session_id: id(1),
            code: TerminationCode::Finished,
            reason: "r".repeat(65_534),
        });
        let wire = encode(&message);
        assert_eq!(wire.get(25..27), Some(&[0xFE, 0xFF][..]));
        let decoded = SessionMessage::decode(&wire).map(|(m, _)| m);
        assert_eq!(decoded, Ok(message));
    }

    #[test]
    fn test_encode_refuses_a_65_535_byte_var_data() {
        let message = SessionMessage::Terminate(Terminate {
            session_id: id(1),
            code: TerminationCode::Finished,
            reason: "r".repeat(65_535),
        });
        let mut wire = Vec::new();
        assert_eq!(
            message.encode(&mut wire),
            Err(FixpEncodeError::VarDataTooLong {
                field: "Reason",
                len: 65_535,
                max: 65_534,
            })
        );
        assert!(wire.is_empty());
        assert!(matches!(
            message.encoded_len(),
            Err(FixpEncodeError::VarDataTooLong { len: 65_535, .. })
        ));
    }

    #[test]
    fn test_decode_rejects_undefined_enum_values() {
        let cases: [(SessionMessage, usize, &str); 6] = [
            (samples().swap_remove(0), 8 + 24, "ClientFlow"),
            (samples().swap_remove(1), 8 + 24, "ServerFlow"),
            (samples().swap_remove(2), 8 + 24, "NegotiationRejectCode"),
            (samples().swap_remove(6), 8 + 24, "EstablishmentRejectCode"),
            (samples().swap_remove(12), 8 + 24, "RetransmitRejectCode"),
            (samples().swap_remove(13), 8 + 16, "TerminationCode"),
        ];
        for (message, offset, field) in cases {
            let mut wire = encode(&message);
            if let Some(slot) = wire.get_mut(offset) {
                *slot = 200;
            }
            assert_eq!(
                SessionMessage::decode(&wire),
                Err(FixpDecodeError::InvalidEnumValue { field, value: 200 }),
                "{}",
                message.name()
            );
        }
        let mut topic = encode(&samples().swap_remove(3));
        if let Some(slot) = topic.get_mut(8 + 16) {
            *slot = 4;
        }
        assert_eq!(
            SessionMessage::decode(&topic),
            Err(FixpDecodeError::InvalidEnumValue {
                field: "Flow",
                value: 4
            })
        );
    }

    #[test]
    fn test_decode_rejects_a_reason_that_is_not_utf8() {
        let mut wire = encode(&SessionMessage::Terminate(Terminate {
            session_id: id(1),
            code: TerminationCode::Finished,
            reason: "ab".to_owned(),
        }));
        if let Some(byte) = wire.get_mut(27) {
            *byte = 0xFF;
        }
        assert_eq!(
            SessionMessage::decode(&wire),
            Err(FixpDecodeError::InvalidUtf8 { field: "Reason" })
        );
    }

    #[test]
    fn test_encode_refuses_a_reason_above_the_length_prefix() {
        let message = SessionMessage::Terminate(Terminate {
            session_id: id(1),
            code: TerminationCode::Finished,
            reason: "r".repeat(MAX_VAR_DATA_LEN + 1),
        });
        let mut wire = vec![1, 2, 3];
        assert_eq!(
            message.encode(&mut wire),
            Err(FixpEncodeError::VarDataTooLong {
                field: "Reason",
                len: MAX_VAR_DATA_LEN + 1,
                max: MAX_VAR_DATA_LEN,
            })
        );
        assert_eq!(wire, vec![1, 2, 3], "nothing is appended on error");
    }

    #[test]
    fn test_encode_into_refuses_a_short_buffer_and_writes_nothing() {
        let message = SessionMessage::Sequence(Sequence { next_seq_no: 1 });
        let mut buf = [0xEE_u8; 15];
        assert_eq!(
            message.encode_into(&mut buf),
            Err(FixpEncodeError::BufferTooSmall {
                needed: 16,
                available: 15,
            })
        );
        assert_eq!(buf, [0xEE; 15]);
        let mut exact = [0_u8; 16];
        assert_eq!(message.encode_into(&mut exact), Ok(16));
    }

    #[test]
    fn test_optional_u64_max_encodes_as_the_null_value() {
        let message = SessionMessage::EstablishmentAck(EstablishmentAck {
            session_id: id(1),
            request_timestamp: Nanotime::from_nanos(1),
            keepalive_interval: 1,
            next_seq_no: Some(u64::MAX),
        });
        let wire = encode(&message);
        match SessionMessage::decode(&wire) {
            Ok((SessionMessage::EstablishmentAck(ack), _)) => assert_eq!(ack.next_seq_no, None),
            other => panic!("unexpected decode result {other:?}"),
        }
    }

    #[test]
    fn test_decode_never_panics_on_arbitrary_bytes() {
        // A deterministic sweep: every template id with every block length
        // from 0 to 40 and a body of patterned bytes of every length to 64.
        for template in 0_u16..=20 {
            for block_length in 0_u16..=40 {
                for body_len in 0_usize..=64 {
                    let mut wire = Vec::with_capacity(HEADER_LEN + body_len);
                    wire.extend_from_slice(&block_length.to_le_bytes());
                    wire.extend_from_slice(&template.to_le_bytes());
                    wire.extend_from_slice(&SCHEMA_ID.to_le_bytes());
                    wire.extend_from_slice(&0_u16.to_le_bytes());
                    wire.extend((0..body_len).map(|i| u8::try_from(i * 37 % 256).unwrap_or(0)));
                    let _ = SessionMessage::decode(&wire);
                }
            }
        }
    }
}
