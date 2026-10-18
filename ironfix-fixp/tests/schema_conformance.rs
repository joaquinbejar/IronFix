/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Checks the codec against the FIXP SBE schema published by FIX Trading
//! Community, vendored verbatim in `spec/SBEschemaForFIXP.xml`.
//!
//! For every `<sbe:message>` of the schema it encodes a sample message and
//! checks the SBE header (template id, block length, schema id and version),
//! the bytes of every root-block field at the offset the schema implies, the
//! null value of every optional field, and the order of the variable-length
//! fields. For every `<enum>` it checks the crate's enumeration has exactly
//! the schema's values under the schema's names.
//!
//! The schema is licensed CC BY-ND 4.0 and is kept out of the published
//! package, so this test is too (see `Cargo.toml`). The parser below reads
//! that one pinned file and nothing else: it is a line scanner for its
//! layout, not an XML parser.

use ironfix_fixp::{
    Applied, Context, Credentials, Establish, EstablishmentAck, EstablishmentReject,
    EstablishmentRejectCode, FinishedReceiving, FinishedSending, FlowType, MessageTemplate,
    Nanotime, Negotiate, NegotiationReject, NegotiationRejectCode, NegotiationResponse, NotApplied,
    Retransmission, RetransmitReject, RetransmitRejectCode, RetransmitRequest, SCHEMA_ID,
    SCHEMA_VERSION, Sequence, SessionId, SessionMessage, Terminate, TerminationCode, Topic,
    UnsequencedHeartbeat,
};
use std::collections::BTreeMap;

const SCHEMA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/spec/SBEschemaForFIXP.xml");

/// A root-block field of the schema.
#[derive(Debug)]
struct SchemaField {
    name: String,
    type_name: String,
    optional: bool,
}

/// An `<sbe:message>` of the schema.
#[derive(Debug, Default)]
struct SchemaMessage {
    name: String,
    fields: Vec<SchemaField>,
    data: Vec<String>,
}

/// What the test reads out of the schema.
#[derive(Debug, Default)]
struct Schema {
    id: u16,
    version: u16,
    byte_order: String,
    /// Encoded size in bytes of each named simple type and enum.
    sizes: BTreeMap<String, usize>,
    /// Valid values of each enum, by name.
    enums: BTreeMap<String, Vec<(String, u8)>>,
    /// Messages by template id.
    messages: BTreeMap<u16, SchemaMessage>,
}

/// The value of attribute `name` on `line`.
fn attr<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let key = format!(" {name}=\"");
    let start = line.find(&key)? + key.len();
    let rest = line.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end)
}

fn primitive_size(primitive: &str) -> usize {
    match primitive {
        "uint8" | "int8" | "char" => 1,
        "uint16" | "int16" => 2,
        "uint32" | "int32" => 4,
        "uint64" | "int64" => 8,
        other => panic!("unexpected primitive type {other}"),
    }
}

fn parse_schema() -> Schema {
    let text = match std::fs::read_to_string(SCHEMA_PATH) {
        Ok(text) => text,
        Err(error) => panic!("cannot read {SCHEMA_PATH}: {error}"),
    };
    let mut schema = Schema::default();
    let mut in_composite = false;
    let mut current_enum: Option<String> = None;
    let mut current_message: Option<u16> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("<sbe:messageSchema") {
            schema.id = attr(line, "id")
                .and_then(|v| v.parse().ok())
                .unwrap_or(u16::MAX);
            schema.version = attr(line, "version")
                .and_then(|v| v.parse().ok())
                .unwrap_or(u16::MAX);
            schema.byte_order = attr(line, "byteOrder").unwrap_or_default().to_owned();
        } else if line.starts_with("<composite") {
            in_composite = true;
        } else if line.starts_with("</composite") {
            in_composite = false;
        } else if line.starts_with("<type ") && !in_composite {
            let (Some(name), Some(primitive)) = (attr(line, "name"), attr(line, "primitiveType"))
            else {
                panic!("unexpected type line {line}");
            };
            let length: usize = attr(line, "length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(1);
            schema
                .sizes
                .insert(name.to_owned(), primitive_size(primitive) * length);
        } else if line.starts_with("<enum") {
            let (Some(name), Some(encoding)) = (attr(line, "name"), attr(line, "encodingType"))
            else {
                panic!("unexpected enum line {line}");
            };
            schema
                .sizes
                .insert(name.to_owned(), primitive_size(encoding));
            schema.enums.insert(name.to_owned(), Vec::new());
            current_enum = Some(name.to_owned());
        } else if line.starts_with("</enum") {
            current_enum = None;
        } else if line.starts_with("<validValue") {
            let Some(enum_name) = current_enum.as_ref() else {
                panic!("validValue outside an enum: {line}");
            };
            let name = attr(line, "name").unwrap_or_default().to_owned();
            let value = line
                .split('>')
                .nth(1)
                .and_then(|rest| rest.split('<').next())
                .and_then(|value| value.trim().parse::<u8>().ok());
            let Some(value) = value else {
                panic!("validValue without a value: {line}");
            };
            if let Some(values) = schema.enums.get_mut(enum_name) {
                values.push((name, value));
            }
        } else if line.starts_with("<sbe:message ") {
            let (Some(name), Some(id)) = (attr(line, "name"), attr(line, "id")) else {
                panic!("unexpected message line {line}");
            };
            let Ok(id) = id.parse::<u16>() else {
                panic!("bad template id in {line}");
            };
            schema.messages.insert(
                id,
                SchemaMessage {
                    name: name.to_owned(),
                    ..SchemaMessage::default()
                },
            );
            current_message = if line.ends_with("/>") { None } else { Some(id) };
        } else if line.starts_with("</sbe:message") {
            current_message = None;
        } else if line.starts_with("<field") {
            let Some(message) = current_message.and_then(|id| schema.messages.get_mut(&id)) else {
                panic!("field outside a message: {line}");
            };
            message.fields.push(SchemaField {
                name: attr(line, "name").unwrap_or_default().to_owned(),
                type_name: attr(line, "type").unwrap_or_default().to_owned(),
                optional: attr(line, "presence") == Some("optional"),
            });
        } else if line.starts_with("<data") {
            let Some(message) = current_message.and_then(|id| schema.messages.get_mut(&id)) else {
                panic!("data outside a message: {line}");
            };
            message
                .data
                .push(attr(line, "name").unwrap_or_default().to_owned());
        }
    }
    schema
}

/// A sample message with the bytes each schema field must encode to.
struct Sample {
    message: SessionMessage,
    fields: BTreeMap<&'static str, Vec<u8>>,
    data: Vec<(&'static str, Vec<u8>)>,
}

fn id(byte: u8) -> SessionId {
    SessionId::from_bytes([byte; 16])
}

fn credentials(bytes: &[u8]) -> Option<Credentials> {
    Credentials::try_new(bytes.to_vec()).ok()
}

fn le64(value: u64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn le32(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn samples() -> Vec<Sample> {
    let sid = id(0x5A);
    let sid_bytes = sid.as_bytes().to_vec();
    let fields = |pairs: Vec<(&'static str, Vec<u8>)>| pairs.into_iter().collect();
    vec![
        Sample {
            message: SessionMessage::Negotiate(Negotiate {
                session_id: sid,
                timestamp: Nanotime::from_nanos(0x1111_2222_3333_4444),
                client_flow: FlowType::Idempotent,
                credentials: credentials(b"cred"),
            }),
            fields: fields(vec![
                ("SessionId", sid_bytes.clone()),
                ("Timestamp", le64(0x1111_2222_3333_4444)),
                ("ClientFlow", vec![1]),
            ]),
            data: vec![("Credentials", b"cred".to_vec())],
        },
        Sample {
            message: SessionMessage::NegotiationResponse(NegotiationResponse {
                session_id: sid,
                request_timestamp: Nanotime::from_nanos(7),
                server_flow: FlowType::Recoverable,
                credentials: credentials(b"srv"),
            }),
            fields: fields(vec![
                ("SessionId", sid_bytes.clone()),
                ("RequestTimestamp", le64(7)),
                ("ServerFlow", vec![0]),
            ]),
            data: vec![("Credentials", b"srv".to_vec())],
        },
        Sample {
            message: SessionMessage::NegotiationReject(NegotiationReject {
                session_id: sid,
                request_timestamp: Nanotime::from_nanos(8),
                code: NegotiationRejectCode::DuplicateId,
                reason: "dup".to_owned(),
            }),
            fields: fields(vec![
                ("SessionId", sid_bytes.clone()),
                ("RequestTimestamp", le64(8)),
                ("Code", vec![2]),
            ]),
            data: vec![("Reason", b"dup".to_vec())],
        },
        Sample {
            message: SessionMessage::Topic(Topic {
                session_id: sid,
                flow: FlowType::Idempotent,
                keepalive_interval: 0x0A0B_0C0D,
                classification: b"cls".to_vec(),
            }),
            fields: fields(vec![
                ("SessionId", sid_bytes.clone()),
                ("Flow", vec![1]),
                ("KeepaliveInterval", le32(0x0A0B_0C0D)),
            ]),
            data: vec![("Classification", b"cls".to_vec())],
        },
        Sample {
            message: SessionMessage::Establish(Establish {
                session_id: sid,
                timestamp: Nanotime::from_nanos(9),
                keepalive_interval: 5_000,
                next_seq_no: Some(0x0102_0304_0506_0708),
                credentials: credentials(b"tok"),
            }),
            fields: fields(vec![
                ("SessionId", sid_bytes.clone()),
                ("Timestamp", le64(9)),
                ("KeepaliveInterval", le32(5_000)),
                ("NextSeqNo", le64(0x0102_0304_0506_0708)),
            ]),
            data: vec![("Credentials", b"tok".to_vec())],
        },
        Sample {
            message: SessionMessage::EstablishmentAck(EstablishmentAck {
                session_id: sid,
                request_timestamp: Nanotime::from_nanos(10),
                keepalive_interval: 6_000,
                next_seq_no: Some(1_000),
            }),
            fields: fields(vec![
                ("SessionId", sid_bytes.clone()),
                ("RequestTimestamp", le64(10)),
                ("KeepaliveInterval", le32(6_000)),
                ("NextSeqNo", le64(1_000)),
            ]),
            data: Vec::new(),
        },
        Sample {
            message: SessionMessage::EstablishmentReject(EstablishmentReject {
                session_id: sid,
                request_timestamp: Nanotime::from_nanos(11),
                code: EstablishmentRejectCode::Credentials,
                reason: "who".to_owned(),
            }),
            fields: fields(vec![
                ("SessionId", sid_bytes.clone()),
                ("RequestTimestamp", le64(11)),
                ("Code", vec![4]),
            ]),
            data: vec![("Reason", b"who".to_vec())],
        },
        Sample {
            message: SessionMessage::Sequence(Sequence { next_seq_no: 12 }),
            fields: fields(vec![("NextSeqNo", le64(12))]),
            data: Vec::new(),
        },
        Sample {
            message: SessionMessage::Context(Context {
                session_id: sid,
                next_seq_no: 13,
            }),
            fields: fields(vec![
                ("SessionId", sid_bytes.clone()),
                ("NextSeqNo", le64(13)),
            ]),
            data: Vec::new(),
        },
        Sample {
            message: SessionMessage::UnsequencedHeartbeat(UnsequencedHeartbeat),
            fields: BTreeMap::new(),
            data: Vec::new(),
        },
        Sample {
            message: SessionMessage::RetransmitRequest(RetransmitRequest {
                session_id: sid,
                timestamp: Nanotime::from_nanos(14),
                from_seq_no: 15,
                count: 16,
            }),
            fields: fields(vec![
                ("SessionId", sid_bytes.clone()),
                ("Timestamp", le64(14)),
                ("FromSeqNo", le64(15)),
                ("Count", le32(16)),
            ]),
            data: Vec::new(),
        },
        Sample {
            message: SessionMessage::Retransmission(Retransmission {
                session_id: sid,
                request_timestamp: Nanotime::from_nanos(17),
                next_seq_no: 18,
                count: 19,
            }),
            fields: fields(vec![
                ("SessionId", sid_bytes.clone()),
                ("RequestTimestamp", le64(17)),
                ("NextSeqNo", le64(18)),
                ("Count", le32(19)),
            ]),
            data: Vec::new(),
        },
        Sample {
            message: SessionMessage::RetransmitReject(RetransmitReject {
                session_id: sid,
                request_timestamp: Nanotime::from_nanos(20),
                code: RetransmitRejectCode::RequestLimitExceeded,
                reason: "lim".to_owned(),
            }),
            fields: fields(vec![
                ("SessionId", sid_bytes.clone()),
                ("RequestTimestamp", le64(20)),
                ("Code", vec![2]),
            ]),
            data: vec![("Reason", b"lim".to_vec())],
        },
        Sample {
            message: SessionMessage::Terminate(Terminate {
                session_id: sid,
                code: TerminationCode::ReRequestOutOfBounds,
                reason: "oob".to_owned(),
            }),
            fields: fields(vec![("SessionId", sid_bytes.clone()), ("Code", vec![2])]),
            data: vec![("Reason", b"oob".to_vec())],
        },
        Sample {
            message: SessionMessage::FinishedSending(FinishedSending {
                session_id: sid,
                last_seq_no: Some(21),
            }),
            fields: fields(vec![
                ("SessionId", sid_bytes.clone()),
                ("LastSeqNo", le64(21)),
            ]),
            data: Vec::new(),
        },
        Sample {
            message: SessionMessage::FinishedReceiving(FinishedReceiving { session_id: sid }),
            fields: fields(vec![("SessionId", sid_bytes)]),
            data: Vec::new(),
        },
        Sample {
            message: SessionMessage::Applied(Applied {
                from_seq_no: 22,
                count: 23,
            }),
            fields: fields(vec![("FromSeqNo", le64(22)), ("Count", le32(23))]),
            data: Vec::new(),
        },
        Sample {
            message: SessionMessage::NotApplied(NotApplied {
                from_seq_no: 24,
                count: 25,
            }),
            fields: fields(vec![("FromSeqNo", le64(24)), ("Count", le32(25))]),
            data: Vec::new(),
        },
        Sample {
            message: SessionMessage::MessageTemplate(MessageTemplate {
                encoding_type: 0x5BE0,
                effective_time: Some(Nanotime::from_nanos(26)),
                version: b"v1".to_vec(),
                template: b"<t/>".to_vec(),
            }),
            fields: fields(vec![
                ("EncodingType", le32(0x5BE0)),
                ("EffectiveTime", le64(26)),
            ]),
            data: vec![("Version", b"v1".to_vec()), ("Template", b"<t/>".to_vec())],
        },
    ]
}

fn encode(message: &SessionMessage) -> Vec<u8> {
    let mut wire = Vec::new();
    if let Err(error) = message.encode(&mut wire) {
        panic!("{} failed to encode: {error}", message.name());
    }
    wire
}

fn u16_at(wire: &[u8], offset: usize) -> u16 {
    match wire.get(offset..offset + 2) {
        Some(&[low, high]) => u16::from_le_bytes([low, high]),
        _ => panic!("no u16 at offset {offset}"),
    }
}

#[test]
fn test_schema_identity_is_the_one_implemented() {
    let schema = parse_schema();
    assert_eq!(schema.id, SCHEMA_ID);
    assert_eq!(schema.version, SCHEMA_VERSION);
    assert_eq!(schema.byte_order, "littleEndian");
    assert_eq!(schema.messages.len(), 19);
}

#[test]
fn test_every_schema_message_matches_the_codec_layout() {
    let schema = parse_schema();
    let samples = samples();
    assert_eq!(
        samples.len(),
        schema.messages.len(),
        "one sample per message"
    );
    for sample in samples {
        let template = sample.message.template_id();
        let Some(spec) = schema.messages.get(&template) else {
            panic!("template {template} is not in the schema");
        };
        let wire = encode(&sample.message);
        let block: usize = spec
            .fields
            .iter()
            .map(|field| match schema.sizes.get(&field.type_name) {
                Some(size) => *size,
                None => panic!("unknown type {} in {}", field.type_name, spec.name),
            })
            .sum();
        // The SBE message header.
        assert_eq!(
            usize::from(u16_at(&wire, 0)),
            block,
            "{} blockLength",
            spec.name
        );
        assert_eq!(u16_at(&wire, 2), template, "{} templateId", spec.name);
        assert_eq!(u16_at(&wire, 4), SCHEMA_ID, "{} schemaId", spec.name);
        assert_eq!(u16_at(&wire, 6), SCHEMA_VERSION, "{} version", spec.name);
        // The sample names exactly the schema's root-block fields.
        let mut schema_names: Vec<&str> = spec.fields.iter().map(|f| f.name.as_str()).collect();
        schema_names.sort_unstable();
        let sample_names: Vec<&str> = sample.fields.keys().copied().collect();
        assert_eq!(
            schema_names, sample_names,
            "{} root-block fields",
            spec.name
        );
        // Root-block fields, contiguous in schema order.
        let mut offset = 8;
        for field in &spec.fields {
            let size = schema.sizes.get(&field.type_name).copied().unwrap_or(0);
            let Some(expected) = sample.fields.get(field.name.as_str()) else {
                panic!("{}.{} has no sample value", spec.name, field.name);
            };
            assert_eq!(expected.len(), size, "{}.{} size", spec.name, field.name);
            assert_eq!(
                wire.get(offset..offset + size),
                Some(expected.as_slice()),
                "{}.{} at offset {}",
                spec.name,
                field.name,
                offset - 8
            );
            offset += size;
        }
        // Variable-length fields after the block, in schema order.
        assert_eq!(
            spec.data,
            sample
                .data
                .iter()
                .map(|(name, _)| (*name).to_owned())
                .collect::<Vec<_>>(),
            "{} data fields",
            spec.name
        );
        for (name, bytes) in &sample.data {
            let len = usize::from(u16_at(&wire, offset));
            assert_eq!(len, bytes.len(), "{}.{} length", spec.name, name);
            assert_eq!(
                wire.get(offset + 2..offset + 2 + len),
                Some(bytes.as_slice()),
                "{}.{} bytes",
                spec.name,
                name
            );
            offset += 2 + len;
        }
        assert_eq!(offset, wire.len(), "{} has no trailing bytes", spec.name);
        // And the bytes decode back to the sample.
        assert_eq!(
            SessionMessage::decode(&wire).map(|(message, _)| message),
            Ok(sample.message.clone())
        );
    }
}

#[test]
fn test_optional_fields_encode_the_uint64_null_value() {
    let schema = parse_schema();
    let optional: Vec<(String, String)> = schema
        .messages
        .values()
        .flat_map(|message| {
            message
                .fields
                .iter()
                .filter(|field| field.optional)
                .map(|field| (message.name.clone(), field.name.clone()))
        })
        .collect();
    assert_eq!(
        optional,
        vec![
            ("Establish".to_owned(), "NextSeqNo".to_owned()),
            ("EstablishmentAck".to_owned(), "NextSeqNo".to_owned()),
            ("FinishedSending".to_owned(), "LastSeqNo".to_owned()),
            ("MessageTemplate".to_owned(), "EffectiveTime".to_owned()),
        ],
        "exactly these fields are Option in the crate"
    );
    let absent = [
        (
            SessionMessage::Establish(Establish {
                session_id: id(1),
                timestamp: Nanotime::from_nanos(1),
                keepalive_interval: 1,
                next_seq_no: None,
                credentials: None,
            }),
            8 + 28,
        ),
        (
            SessionMessage::EstablishmentAck(EstablishmentAck {
                session_id: id(1),
                request_timestamp: Nanotime::from_nanos(1),
                keepalive_interval: 1,
                next_seq_no: None,
            }),
            8 + 28,
        ),
        (
            SessionMessage::FinishedSending(FinishedSending {
                session_id: id(1),
                last_seq_no: None,
            }),
            8 + 16,
        ),
        (
            SessionMessage::MessageTemplate(MessageTemplate {
                encoding_type: 1,
                effective_time: None,
                version: Vec::new(),
                template: Vec::new(),
            }),
            8 + 4,
        ),
    ];
    for (message, offset) in absent {
        let wire = encode(&message);
        assert_eq!(
            wire.get(offset..offset + 8),
            Some(&[0xFF; 8][..]),
            "{} absent field",
            message.name()
        );
    }
}

/// Checks an enumeration against the schema: same names, same values, and
/// nothing else.
fn check_enum(schema: &Schema, name: &str, decode: impl Fn(u8) -> Option<String>) {
    let Some(values) = schema.enums.get(name) else {
        panic!("enum {name} is not in the schema");
    };
    for (variant, value) in values {
        assert_eq!(
            decode(*value).as_deref(),
            Some(variant.as_str()),
            "{name} {value}"
        );
    }
    let defined: Vec<u8> = values.iter().map(|(_, value)| *value).collect();
    for value in 0..=u8::MAX {
        if !defined.contains(&value) {
            assert_eq!(decode(value), None, "{name} must refuse {value}");
        }
    }
}

#[test]
fn test_every_schema_enum_matches_the_crate() {
    let schema = parse_schema();
    assert_eq!(schema.enums.len(), 5);
    check_enum(&schema, "FlowType", |v| {
        FlowType::from_u8(v).map(|e| format!("{e:?}"))
    });
    check_enum(&schema, "NegotiationRejectCode", |v| {
        NegotiationRejectCode::from_u8(v).map(|e| format!("{e:?}"))
    });
    check_enum(&schema, "EstablishmentRejectCode", |v| {
        EstablishmentRejectCode::from_u8(v).map(|e| format!("{e:?}"))
    });
    check_enum(&schema, "RetransmitRejectCode", |v| {
        RetransmitRejectCode::from_u8(v).map(|e| format!("{e:?}"))
    });
    check_enum(&schema, "TerminationCode", |v| {
        TerminationCode::from_u8(v).map(|e| format!("{e:?}"))
    });
}

#[test]
fn test_message_names_match_the_schema_but_one_upstream_typo() {
    let schema = parse_schema();
    for sample in samples() {
        let template = sample.message.template_id();
        let Some(spec) = schema.messages.get(&template) else {
            panic!("template {template} is not in the schema");
        };
        if template == RetransmitReject::TEMPLATE_ID {
            // The schema spells it "RestransmitReject"; the text does not.
            assert_eq!(spec.name, "RestransmitReject");
            assert_eq!(sample.message.name(), "RetransmitReject");
        } else {
            assert_eq!(spec.name, sample.message.name());
        }
    }
}
