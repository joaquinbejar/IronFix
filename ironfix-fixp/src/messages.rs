/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The FIXP session messages, one struct per `<sbe:message>` of the FIXP SBE
//! schema (id 2748, version 0), and [`SessionMessage`], their sum.
//!
//! Field names follow the schema in `snake_case`. Wire types map as:
//!
//! | Schema type | Rust type |
//! |---|---|
//! | `UUID` | [`SessionId`] |
//! | `nanotime` | [`Nanotime`] |
//! | `DeltaMillisecs` | `u32`, milliseconds |
//! | `ordinal` | `u64` (a sequence number) |
//! | `cardinal` | `u32` (a message count) |
//! | an `enum` | its Rust enum in [`crate::types`] |
//! | `Object` | `Vec<u8>`, or [`Credentials`] |
//! | `CharacterString` | `String` |
//!
//! Optional fields are `Option`s. On the wire an absent `ordinal` or
//! `nanotime` is the SBE `uint64` null value, `u64::MAX`, so `Some(u64::MAX)`
//! cannot be sent and encodes as absent. An absent variable-length field is a
//! zero-length one: `None` credentials and empty credentials both encode as
//! length 0 and decode as `None`, and an empty `reason` means "no reason".
//!
//! Sequence numbers are raw `u64`s here because these structs carry what is
//! on the wire, including values the session rejects (a `NextSeqNo` of 0, for
//! instance). The session core validates them; the codec does not.
//!
//! The layouts are the SBE defaults the schema implies: fields of the root
//! block contiguous in schema order with no padding, then the
//! variable-length fields in schema order, each as a `uint16` length and its
//! bytes. `tests/schema_conformance.rs` checks every template id, block
//! length, field offset and enum value against the vendored schema.

use crate::types::{
    Credentials, EstablishmentRejectCode, FlowType, Nanotime, NegotiationRejectCode,
    RetransmitRejectCode, SessionId, TerminationCode,
};

/// The SBE `schemaId` of the FIXP session messages.
pub const SCHEMA_ID: u16 = 2748;

/// The SBE `version` of the FIXP session schema this crate implements.
pub const SCHEMA_VERSION: u16 = 0;

/// Declares the template id, root block length and name of a message.
macro_rules! layout {
    ($ty:ty, $name:literal, template = $template:literal, block = $block:literal) => {
        impl $ty {
            /// The SBE `templateId` of this message.
            pub const TEMPLATE_ID: u16 = $template;
            /// The length of the root block in schema version 0, in bytes.
            pub const BLOCK_LENGTH: u16 = $block;
            /// The message name in the schema.
            pub const NAME: &'static str = $name;
        }
    };
}

/// Negotiate: the client asks to create a logical session (FIXP v1.1
/// section 4.2.1). Template 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiate {
    /// The identifier of the session being created, assigned by the client.
    pub session_id: SessionId,
    /// Wall-clock time of the request. The answer carries it back as
    /// `RequestTimestamp`, which is how the two are matched.
    pub timestamp: Nanotime,
    /// The delivery guarantee the client wants for the messages it sends
    /// (section 3.4.4).
    pub client_flow: FlowType,
    /// The client's proof of identity, in a format the counterparties agree
    /// on (section 3.4.2). Never logged.
    pub credentials: Option<Credentials>,
}
layout!(Negotiate, "Negotiate", template = 1, block = 25);

/// NegotiationResponse: the server accepts a Negotiate (FIXP v1.1
/// section 4.2.2). Template 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationResponse {
    /// The session identifier from the Negotiate.
    pub session_id: SessionId,
    /// The `Timestamp` of the Negotiate being answered.
    pub request_timestamp: Nanotime,
    /// The delivery guarantee the server gives the messages it sends
    /// (section 3.4.4).
    pub server_flow: FlowType,
    /// The server's proof of identity, for mutual authentication
    /// (section 4.2.2). Never logged.
    pub credentials: Option<Credentials>,
}
layout!(
    NegotiationResponse,
    "NegotiationResponse",
    template = 2,
    block = 25
);

/// NegotiationReject: the server refuses a Negotiate (FIXP v1.1
/// section 4.2.3). Template 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationReject {
    /// The session identifier from the Negotiate.
    pub session_id: SessionId,
    /// The `Timestamp` of the Negotiate being answered.
    pub request_timestamp: Nanotime,
    /// The reason code.
    pub code: NegotiationRejectCode,
    /// Free text for people; empty if the sender gave none.
    pub reason: String,
}
layout!(
    NegotiationReject,
    "NegotiationReject",
    template = 3,
    block = 25
);

/// Topic: announces a multicast flow (FIXP v1.1 section 5.1.1.1).
/// Template 4. Multicast only: the point-to-point session core treats it as a
/// protocol violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topic {
    /// The identifier of the multicast flow.
    pub session_id: SessionId,
    /// The delivery guarantee of the flow (section 5.1.1.1).
    pub flow: FlowType,
    /// The publisher's keepalive interval, in milliseconds.
    pub keepalive_interval: u32,
    /// Opaque bytes naming what the flow is about, for instance a product
    /// or a symbol (section 5.1.1.1).
    pub classification: Vec<u8>,
}
layout!(Topic, "Topic", template = 4, block = 21);

/// Establish: the client binds the session to the transport (FIXP v1.1
/// section 4.3.1). Template 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Establish {
    /// The identifier of the session being bound.
    pub session_id: SessionId,
    /// Wall-clock time of the request. The answer carries it back as
    /// `RequestTimestamp`, which is how the two are matched.
    pub timestamp: Nanotime,
    /// The client's keepalive interval in milliseconds: it sends a heartbeat
    /// whenever this long passes without an application message
    /// (section 4.5).
    pub keepalive_interval: u32,
    /// Where the client's own numbering stands: the number its next
    /// application message will carry. Used to spot messages the server
    /// missed on a re-establishment (section 4.3.1).
    pub next_seq_no: Option<u64>,
    /// The client's proof of identity, in a format the counterparties agree
    /// on (section 3.4.2). Never logged.
    pub credentials: Option<Credentials>,
}
layout!(Establish, "Establish", template = 5, block = 36);

/// EstablishmentAck: the server accepts an Establish (FIXP v1.1
/// section 4.3.2). Template 6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishmentAck {
    /// The session identifier from the Establish.
    pub session_id: SessionId,
    /// The `Timestamp` of the Establish being answered.
    pub request_timestamp: Nanotime,
    /// The server's keepalive interval in milliseconds (section 4.5).
    pub keepalive_interval: u32,
    /// Where the server's own numbering stands: the number its next
    /// application message will carry. Used to spot messages the client
    /// missed (section 4.3.2).
    pub next_seq_no: Option<u64>,
}
layout!(
    EstablishmentAck,
    "EstablishmentAck",
    template = 6,
    block = 36
);

/// EstablishmentReject: the server refuses an Establish (FIXP v1.1
/// section 4.3.3). Template 7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishmentReject {
    /// The session identifier from the Establish.
    pub session_id: SessionId,
    /// The `Timestamp` of the Establish being answered.
    pub request_timestamp: Nanotime,
    /// The reason code.
    pub code: EstablishmentRejectCode,
    /// Free text for people; empty if the sender gave none.
    pub reason: String,
}
layout!(
    EstablishmentReject,
    "EstablishmentReject",
    template = 7,
    block = 25
);

/// Sequence: starts a sequenced run of application messages, and is the
/// heartbeat of a sequenced flow (FIXP v1.1 sections 3.5.1 and 4.5).
/// Template 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sequence {
    /// The number the receiver gives to the first application message
    /// after this one; later ones count up from it (section 3.5.1).
    pub next_seq_no: u64,
}
layout!(Sequence, "Sequence", template = 8, block = 8);

/// Context: a Sequence that also names the session, for multiplexed
/// transports (FIXP v1.1 section 3.5.3). Template 9.
///
/// The section 3.5.3 table marks `NextSeqNo` optional but the schema declares
/// it required (no `presence="optional"`); this crate follows the schema, the
/// wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    /// The session the following messages belong to.
    pub session_id: SessionId,
    /// As in [`Sequence::next_seq_no`]. The session core reads `u64::MAX`,
    /// the SBE null value of an optional `uint64`, as "no number given".
    pub next_seq_no: u64,
}
layout!(Context, "Context", template = 9, block = 24);

/// UnsequencedHeartbeat: the heartbeat of an Unsequenced or None flow
/// (FIXP v1.1 section 4.5). Template 10, no fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnsequencedHeartbeat;
layout!(
    UnsequencedHeartbeat,
    "UnsequencedHeartbeat",
    template = 10,
    block = 0
);

/// RetransmitRequest: asks the producer of a recoverable flow to resend
/// messages (FIXP v1.1 section 4.6.1). Template 11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetransmitRequest {
    /// The session the messages belong to.
    pub session_id: SessionId,
    /// Wall-clock time of the request. Answers carry it back as
    /// `RequestTimestamp`, which is how they are matched to it.
    pub timestamp: Nanotime,
    /// Start of the range asked for (section 4.6.1).
    pub from_seq_no: u64,
    /// Length of the range asked for, in messages.
    pub count: u32,
}
layout!(
    RetransmitRequest,
    "RetransmitRequest",
    template = 11,
    block = 36
);

/// Retransmission: precedes a batch of retransmitted messages (FIXP v1.1
/// section 4.6.2). Template 12.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retransmission {
    /// The session the messages belong to.
    pub session_id: SessionId,
    /// The `Timestamp` of the RetransmitRequest being answered.
    pub request_timestamp: Nanotime,
    /// The number the receiver gives to the first replayed message that
    /// follows (section 4.6.2).
    pub next_seq_no: u64,
    /// How many replayed messages follow this header.
    pub count: u32,
}
layout!(Retransmission, "Retransmission", template = 12, block = 36);

/// RetransmitReject: refuses a RetransmitRequest (FIXP v1.1
/// section 4.6.2.3). Template 13.
///
/// The schema spells this message `RestransmitReject`; the specification
/// text, and this crate, spell it `RetransmitReject`. The template id is what
/// goes on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetransmitReject {
    /// The session named by the request.
    pub session_id: SessionId,
    /// The `Timestamp` of the RetransmitRequest being answered.
    pub request_timestamp: Nanotime,
    /// The reason code.
    pub code: RetransmitRejectCode,
    /// Free text for people; empty if the sender gave none.
    pub reason: String,
}
layout!(
    RetransmitReject,
    "RetransmitReject",
    template = 13,
    block = 25
);

/// Terminate: unbinds the transport from the session (FIXP v1.1
/// section 4.4). Template 14.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terminate {
    /// The session being unbound.
    pub session_id: SessionId,
    /// The termination code.
    pub code: TerminationCode,
    /// Free text for people; empty if the sender gave none.
    pub reason: String,
}
layout!(Terminate, "Terminate", template = 14, block = 17);

/// FinishedSending: the sender starts closing its flow for good (FIXP v1.1
/// section 4.7.1). Template 15. The session core answers it; it never sends
/// one (see the crate documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinishedSending {
    /// The session being finalized.
    pub session_id: SessionId,
    /// On a numbered flow, the number of the sender's final application
    /// message, which lets the receiver check it is missing nothing.
    pub last_seq_no: Option<u64>,
}
layout!(
    FinishedSending,
    "FinishedSending",
    template = 15,
    block = 24
);

/// FinishedReceiving: acknowledges a FinishedSending (FIXP v1.1
/// section 4.7.2). Template 16.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinishedReceiving {
    /// The session being finalized.
    pub session_id: SessionId,
}
layout!(
    FinishedReceiving,
    "FinishedReceiving",
    template = 16,
    block = 16
);

/// Applied: tells the sender of an Idempotent flow that a range of its
/// operations took effect (FIXP v1.1 section 4.8.1). Template 17. It travels
/// as an application message, so on a numbered flow it takes a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// Start of the range that took effect.
    pub from_seq_no: u64,
    /// Length of that range, in messages.
    pub count: u32,
}
layout!(Applied, "Applied", template = 17, block = 12);

/// NotApplied: tells the sender of an Idempotent flow that a range of its
/// numbers never arrived, so those operations did not take effect (FIXP v1.1
/// section 4.8.2). Template 18. It travels as an application message, so on
/// a numbered flow it takes a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotApplied {
    /// Start of the range that never arrived.
    pub from_seq_no: u64,
    /// Length of that range, in messages.
    pub count: u32,
}
layout!(NotApplied, "NotApplied", template = 18, block = 12);

/// MessageTemplate: in-band delivery of a template or schema (FIXP v1.1
/// section 3.6). Template 19. Passed through by the session core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageTemplate {
    /// The encoding the template belongs to, as a SOFH `Encoding_Type`
    /// code (section 3.6).
    pub encoding_type: u32,
    /// Wall-clock time from which the template applies, or `None` to apply
    /// it at once.
    pub effective_time: Option<Nanotime>,
    /// Opaque bytes identifying which revision of the template this is;
    /// empty if the sender gave none.
    pub version: Vec<u8>,
    /// The template or schema document, as opaque bytes.
    pub template: Vec<u8>,
}
layout!(
    MessageTemplate,
    "MessageTemplate",
    template = 19,
    block = 12
);

/// Any FIXP session message: one variant per template of the schema.
///
/// Exhaustive on purpose: the set is fixed by schema version 0, and the
/// session core matches it without a wildcard arm so that no message can be
/// handled by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionMessage {
    /// Template 1.
    Negotiate(Negotiate),
    /// Template 2.
    NegotiationResponse(NegotiationResponse),
    /// Template 3.
    NegotiationReject(NegotiationReject),
    /// Template 4.
    Topic(Topic),
    /// Template 5.
    Establish(Establish),
    /// Template 6.
    EstablishmentAck(EstablishmentAck),
    /// Template 7.
    EstablishmentReject(EstablishmentReject),
    /// Template 8.
    Sequence(Sequence),
    /// Template 9.
    Context(Context),
    /// Template 10.
    UnsequencedHeartbeat(UnsequencedHeartbeat),
    /// Template 11.
    RetransmitRequest(RetransmitRequest),
    /// Template 12.
    Retransmission(Retransmission),
    /// Template 13.
    RetransmitReject(RetransmitReject),
    /// Template 14.
    Terminate(Terminate),
    /// Template 15.
    FinishedSending(FinishedSending),
    /// Template 16.
    FinishedReceiving(FinishedReceiving),
    /// Template 17.
    Applied(Applied),
    /// Template 18.
    NotApplied(NotApplied),
    /// Template 19.
    MessageTemplate(MessageTemplate),
}

impl SessionMessage {
    /// Returns the SBE `templateId` of the message.
    #[must_use]
    pub const fn template_id(&self) -> u16 {
        match self {
            Self::Negotiate(_) => Negotiate::TEMPLATE_ID,
            Self::NegotiationResponse(_) => NegotiationResponse::TEMPLATE_ID,
            Self::NegotiationReject(_) => NegotiationReject::TEMPLATE_ID,
            Self::Topic(_) => Topic::TEMPLATE_ID,
            Self::Establish(_) => Establish::TEMPLATE_ID,
            Self::EstablishmentAck(_) => EstablishmentAck::TEMPLATE_ID,
            Self::EstablishmentReject(_) => EstablishmentReject::TEMPLATE_ID,
            Self::Sequence(_) => Sequence::TEMPLATE_ID,
            Self::Context(_) => Context::TEMPLATE_ID,
            Self::UnsequencedHeartbeat(_) => UnsequencedHeartbeat::TEMPLATE_ID,
            Self::RetransmitRequest(_) => RetransmitRequest::TEMPLATE_ID,
            Self::Retransmission(_) => Retransmission::TEMPLATE_ID,
            Self::RetransmitReject(_) => RetransmitReject::TEMPLATE_ID,
            Self::Terminate(_) => Terminate::TEMPLATE_ID,
            Self::FinishedSending(_) => FinishedSending::TEMPLATE_ID,
            Self::FinishedReceiving(_) => FinishedReceiving::TEMPLATE_ID,
            Self::Applied(_) => Applied::TEMPLATE_ID,
            Self::NotApplied(_) => NotApplied::TEMPLATE_ID,
            Self::MessageTemplate(_) => MessageTemplate::TEMPLATE_ID,
        }
    }

    /// Returns the message name, as the specification text spells it.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Negotiate(_) => Negotiate::NAME,
            Self::NegotiationResponse(_) => NegotiationResponse::NAME,
            Self::NegotiationReject(_) => NegotiationReject::NAME,
            Self::Topic(_) => Topic::NAME,
            Self::Establish(_) => Establish::NAME,
            Self::EstablishmentAck(_) => EstablishmentAck::NAME,
            Self::EstablishmentReject(_) => EstablishmentReject::NAME,
            Self::Sequence(_) => Sequence::NAME,
            Self::Context(_) => Context::NAME,
            Self::UnsequencedHeartbeat(_) => UnsequencedHeartbeat::NAME,
            Self::RetransmitRequest(_) => RetransmitRequest::NAME,
            Self::Retransmission(_) => Retransmission::NAME,
            Self::RetransmitReject(_) => RetransmitReject::NAME,
            Self::Terminate(_) => Terminate::NAME,
            Self::FinishedSending(_) => FinishedSending::NAME,
            Self::FinishedReceiving(_) => FinishedReceiving::NAME,
            Self::Applied(_) => Applied::NAME,
            Self::NotApplied(_) => NotApplied::NAME,
            Self::MessageTemplate(_) => MessageTemplate::NAME,
        }
    }

    /// Returns the session identifier the message carries, if it has one.
    ///
    /// A driver serving several sessions routes Negotiate and Establish by
    /// it. Sequence, UnsequencedHeartbeat, Applied, NotApplied and
    /// MessageTemplate carry none: on a non-multiplexed transport the
    /// transport implies the session.
    #[must_use]
    pub const fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::Negotiate(m) => Some(m.session_id),
            Self::NegotiationResponse(m) => Some(m.session_id),
            Self::NegotiationReject(m) => Some(m.session_id),
            Self::Topic(m) => Some(m.session_id),
            Self::Establish(m) => Some(m.session_id),
            Self::EstablishmentAck(m) => Some(m.session_id),
            Self::EstablishmentReject(m) => Some(m.session_id),
            Self::Context(m) => Some(m.session_id),
            Self::RetransmitRequest(m) => Some(m.session_id),
            Self::Retransmission(m) => Some(m.session_id),
            Self::RetransmitReject(m) => Some(m.session_id),
            Self::Terminate(m) => Some(m.session_id),
            Self::FinishedSending(m) => Some(m.session_id),
            Self::FinishedReceiving(m) => Some(m.session_id),
            Self::Sequence(_)
            | Self::UnsequencedHeartbeat(_)
            | Self::Applied(_)
            | Self::NotApplied(_)
            | Self::MessageTemplate(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_ids_are_one_to_nineteen_in_schema_order() {
        let ids = [
            Negotiate::TEMPLATE_ID,
            NegotiationResponse::TEMPLATE_ID,
            NegotiationReject::TEMPLATE_ID,
            Topic::TEMPLATE_ID,
            Establish::TEMPLATE_ID,
            EstablishmentAck::TEMPLATE_ID,
            EstablishmentReject::TEMPLATE_ID,
            Sequence::TEMPLATE_ID,
            Context::TEMPLATE_ID,
            UnsequencedHeartbeat::TEMPLATE_ID,
            RetransmitRequest::TEMPLATE_ID,
            Retransmission::TEMPLATE_ID,
            RetransmitReject::TEMPLATE_ID,
            Terminate::TEMPLATE_ID,
            FinishedSending::TEMPLATE_ID,
            FinishedReceiving::TEMPLATE_ID,
            Applied::TEMPLATE_ID,
            NotApplied::TEMPLATE_ID,
            MessageTemplate::TEMPLATE_ID,
        ];
        for (index, id) in ids.iter().enumerate() {
            assert_eq!(usize::from(*id), index + 1);
        }
    }

    #[test]
    fn test_session_message_names_and_session_ids() {
        let id = SessionId::from_bytes([7; 16]);
        let terminate = SessionMessage::Terminate(Terminate {
            session_id: id,
            code: TerminationCode::Finished,
            reason: String::new(),
        });
        assert_eq!(terminate.name(), "Terminate");
        assert_eq!(terminate.template_id(), 14);
        assert_eq!(terminate.session_id(), Some(id));
        let sequence = SessionMessage::Sequence(Sequence { next_seq_no: 1 });
        assert_eq!(sequence.session_id(), None);
        assert_eq!(sequence.name(), "Sequence");
    }
}
