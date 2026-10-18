/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The dictionaries whose generated views, enumerations and writers are
//! compiled as golden files.
//!
//! - `views_sample_dictionary`: small and hand-built, carrying every shape
//!   the view generator has to get right (see its docs).
//! - `fix44_order_dictionary`: the embedded FIX 4.4 dictionary with only
//!   Heartbeat (0), Logon (A) and NewOrderSingle (D) kept. The full FIX 4.4
//!   views are about 3.7 MB, too large to commit; every FIX 4.4 component,
//!   field and the header are kept, so these three messages generate exactly
//!   as they do from the full dictionary.
//! - the embedded FIXT 1.1 dictionary, in full.

use ironfix_codegen::CodeGenerator;
use ironfix_dictionary::schema::{
    ComponentDef, ComponentRef, Dictionary, FieldDef, FieldRef as SchemaFieldRef, FieldType,
    GroupDef, MessageCategory, MessageDef, Version,
};
use std::collections::HashMap;

/// Builds a field reference.
fn field_ref(tag: u32, name: &str, required: bool) -> SchemaFieldRef {
    SchemaFieldRef {
        tag,
        name: name.to_string(),
        required,
    }
}

/// Builds a value table from `(wire value, description)` pairs.
fn values(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(value, description)| (value.to_string(), description.to_string()))
        .collect()
}

/// A hand-built dictionary covering every shape the view generator handles:
///
/// - a header with a repeating group (NoHops) and a trailer;
/// - a required component (Instrument) and an optional one (Parties) whose
///   group nests a group through a further component (PtysSubGrp), shared by
///   two messages so its view and writer are generated once;
/// - a group declared inline in a message (NoAllocs);
/// - Text (58) both at the message level and inside a NoPartyIDs entry;
/// - a char enumeration, a multi-value enumeration, a `Boolean` with declared
///   values (read as `bool`), a decimal, a `data` field, a keyword field
///   (Yield), a plain `char` (Flag), two names that fold onto one identifier
///   (ClOrdID / ClOrdId), a reserved method name (Get) and a `to_` name
///   (ToVenue);
/// - an enumeration whose values exercise variant naming: an empty
///   description, the fallback name `OTHER`, the keyword `SELF`, a leading
///   digit, a name ending with the enumeration's, two descriptions folding
///   onto one name, and wire values needing escapes;
/// - a message with no fields at all.
#[must_use]
pub fn views_sample_dictionary() -> Dictionary {
    let mut dict = Dictionary::new(Version::Fix44);

    for (tag, name, field_type) in [
        (1u32, "Account", FieldType::String),
        (8, "BeginString", FieldType::String),
        (9, "BodyLength", FieldType::Length),
        (10, "CheckSum", FieldType::String),
        (11, "ClOrdID", FieldType::String),
        (12, "ClOrdId", FieldType::String),
        (34, "MsgSeqNum", FieldType::SeqNum),
        (35, "MsgType", FieldType::String),
        (38, "OrderQty", FieldType::Qty),
        (44, "Price", FieldType::Price),
        (49, "SenderCompID", FieldType::String),
        (52, "SendingTime", FieldType::UtcTimestamp),
        (55, "Symbol", FieldType::String),
        (56, "TargetCompID", FieldType::String),
        (58, "Text", FieldType::String),
        (60, "TransactTime", FieldType::UtcTimestamp),
        (78, "NoAllocs", FieldType::NumInGroup),
        (79, "AllocAccount", FieldType::String),
        (80, "AllocQty", FieldType::Qty),
        (95, "RawDataLength", FieldType::Length),
        (96, "RawData", FieldType::Data),
        (236, "Yield", FieldType::Percentage),
        (448, "PartyID", FieldType::String),
        (452, "PartyRole", FieldType::Int),
        (453, "NoPartyIDs", FieldType::NumInGroup),
        (523, "PartySubID", FieldType::String),
        (627, "NoHops", FieldType::NumInGroup),
        (628, "HopCompID", FieldType::String),
        (802, "NoPartySubIDs", FieldType::NumInGroup),
        (803, "PartySubIDType", FieldType::Int),
        (5000, "ToVenue", FieldType::String),
        (5001, "Get", FieldType::String),
        (5002, "Flag", FieldType::Char),
    ] {
        dict.add_field(FieldDef::new(tag, name, field_type));
    }
    dict.add_field(
        FieldDef::new(18, "ExecInst", FieldType::MultipleStringValue).with_values(values(&[
            ("1", "NOT_HELD"),
            ("2", "WORK"),
            ("G", "ALL_OR_NONE"),
        ])),
    );
    dict.add_field(
        FieldDef::new(54, "Side", FieldType::Char).with_values(values(&[
            ("1", "BUY"),
            ("2", "SELL"),
            ("8", "CROSS"),
        ])),
    );
    dict.add_field(
        FieldDef::new(114, "LocateReqd", FieldType::Boolean)
            .with_values(values(&[("N", "NO"), ("Y", "YES")])),
    );
    dict.add_field(
        FieldDef::new(167, "SecurityType", FieldType::String).with_values(values(&[
            ("?", ""),
            ("1D", "1_DAY"),
            ("CS", "COMMON_STOCK"),
            ("EURIBOR", "EURIBOR"),
            ("Euribor", "EURIBOR"),
            ("NONE", "NO_SECURITY_TYPE"),
            ("OTHER", "OTHER"),
            ("Q\"\\", "QUOTED"),
            ("SELF", "SELF"),
            ("\u{c9}", "E_ACUTE"),
        ])),
    );
    dict.add_field(
        FieldDef::new(447, "PartyIDSource", FieldType::Char)
            .with_values(values(&[("D", "PROPRIETARY"), ("9", "OTHER")])),
    );

    dict.header = vec![
        field_ref(8, "BeginString", true),
        field_ref(9, "BodyLength", true),
        field_ref(35, "MsgType", true),
        field_ref(49, "SenderCompID", true),
        field_ref(56, "TargetCompID", true),
        field_ref(34, "MsgSeqNum", true),
        field_ref(52, "SendingTime", true),
    ];
    dict.header_groups = vec![GroupDef {
        count_tag: 627,
        name: "NoHops".to_string(),
        delimiter_tag: 628,
        fields: vec![field_ref(628, "HopCompID", false)],
        groups: Vec::new(),
        components: Vec::new(),
        required: false,
    }];
    dict.trailer = vec![field_ref(10, "CheckSum", true)];

    dict.add_component(ComponentDef {
        name: "Instrument".to_string(),
        fields: vec![
            field_ref(55, "Symbol", true),
            field_ref(167, "SecurityType", false),
        ],
        groups: Vec::new(),
        components: Vec::new(),
    });
    dict.add_component(ComponentDef {
        name: "PtysSubGrp".to_string(),
        fields: Vec::new(),
        groups: vec![GroupDef {
            count_tag: 802,
            name: "NoPartySubIDs".to_string(),
            delimiter_tag: 523,
            fields: vec![
                field_ref(523, "PartySubID", false),
                field_ref(803, "PartySubIDType", false),
            ],
            groups: Vec::new(),
            components: Vec::new(),
            required: false,
        }],
        components: Vec::new(),
    });
    dict.add_component(ComponentDef {
        name: "Parties".to_string(),
        fields: Vec::new(),
        groups: vec![GroupDef {
            count_tag: 453,
            name: "NoPartyIDs".to_string(),
            delimiter_tag: 448,
            fields: vec![
                field_ref(448, "PartyID", false),
                field_ref(447, "PartyIDSource", false),
                field_ref(452, "PartyRole", true),
                field_ref(58, "Text", false),
            ],
            groups: Vec::new(),
            components: vec![ComponentRef::new("PtysSubGrp", false)],
            required: false,
        }],
        components: Vec::new(),
    });

    dict.add_message(MessageDef {
        msg_type: "D".to_string(),
        name: "NewOrderSingle".to_string(),
        category: MessageCategory::App,
        fields: vec![
            field_ref(11, "ClOrdID", true),
            field_ref(12, "ClOrdId", false),
            field_ref(1, "Account", false),
            field_ref(54, "Side", true),
            field_ref(60, "TransactTime", true),
            field_ref(38, "OrderQty", false),
            field_ref(44, "Price", false),
            field_ref(18, "ExecInst", false),
            field_ref(114, "LocateReqd", false),
            field_ref(95, "RawDataLength", false),
            field_ref(96, "RawData", false),
            field_ref(236, "Yield", false),
            field_ref(58, "Text", false),
            field_ref(5000, "ToVenue", false),
            field_ref(5001, "Get", false),
            field_ref(5002, "Flag", false),
        ],
        groups: vec![GroupDef {
            count_tag: 78,
            name: "NoAllocs".to_string(),
            delimiter_tag: 79,
            fields: vec![
                field_ref(79, "AllocAccount", false),
                field_ref(80, "AllocQty", false),
            ],
            groups: Vec::new(),
            components: Vec::new(),
            required: false,
        }],
        components: vec![
            ComponentRef::new("Instrument", true),
            ComponentRef::new("Parties", false),
        ],
    });
    dict.add_message(MessageDef {
        msg_type: "8".to_string(),
        name: "ExecutionReport".to_string(),
        category: MessageCategory::App,
        fields: vec![
            field_ref(11, "ClOrdID", true),
            field_ref(54, "Side", true),
            field_ref(58, "Text", false),
        ],
        groups: Vec::new(),
        components: vec![
            ComponentRef::new("Instrument", true),
            ComponentRef::new("Parties", false),
        ],
    });
    dict.add_message(MessageDef {
        msg_type: "0".to_string(),
        name: "Heartbeat".to_string(),
        category: MessageCategory::Admin,
        fields: Vec::new(),
        groups: Vec::new(),
        components: Vec::new(),
    });

    dict
}

/// The embedded FIX 4.4 dictionary with only Heartbeat (0), Logon (A) and
/// NewOrderSingle (D) kept.
#[track_caller]
#[must_use]
pub fn fix44_order_dictionary() -> Dictionary {
    let mut dict = match Dictionary::fix44() {
        Ok(dict) => dict.clone(),
        Err(err) => panic!("the embedded FIX 4.4 dictionary must load: {err}"),
    };
    dict.messages
        .retain(|msg_type, _| matches!(msg_type.as_str(), "0" | "A" | "D"));
    dict
}

/// Generates views from `dict`, failing the test on a generator error.
#[track_caller]
fn generate(dict: &Dictionary, what: &str) -> String {
    match CodeGenerator::new().generate_views(dict) {
        Ok(code) => code,
        Err(err) => panic!("the {what} views must generate: {err}"),
    }
}

/// Generates the views of [`views_sample_dictionary`]
/// (`golden/views_sample.rs`).
#[track_caller]
#[must_use]
pub fn generate_views_sample() -> String {
    generate(&views_sample_dictionary(), "sample")
}

/// Generates the views of [`fix44_order_dictionary`]
/// (`golden/views_fix44_order.rs`).
#[track_caller]
#[must_use]
pub fn generate_views_fix44_order() -> String {
    generate(&fix44_order_dictionary(), "FIX 4.4 order")
}

/// Generates the views of the embedded FIXT 1.1 dictionary
/// (`golden/views_fixt11.rs`).
#[track_caller]
#[must_use]
pub fn generate_views_fixt11() -> String {
    match Dictionary::fixt11() {
        Ok(dict) => generate(dict, "FIXT 1.1"),
        Err(err) => panic!("the embedded FIXT 1.1 dictionary must load: {err}"),
    }
}
