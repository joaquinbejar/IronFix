/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Compiles the generated views, enumerations and writers, and drives them
//! over real frames.
//!
//! Three golden files, each `CodeGenerator::generate_views` output, are
//! compiled here against the real `ironfix-core`, `ironfix-dictionary` and
//! `rust_decimal`:
//!
//! - `golden/views_sample.rs`: the hand-built sample in `views_common`;
//! - `golden/views_fix44_order.rs`: FIX 4.4 Heartbeat, Logon and
//!   NewOrderSingle, generated from the embedded dictionary;
//! - `golden/views_fixt11.rs`: the embedded FIXT 1.1 dictionary in full.
//!
//! The `matches_the_compiled_golden_file` test asserts the generator still
//! produces them. Regenerate after an intentional change with:
//!
//! ```text
//! cargo test -p ironfix-codegen --test regenerate_golden -- --ignored
//! ```
//!
//! The generated text carries no `#[allow]`. The `#[allow(dead_code)]` on
//! the modules below belongs to this test binary, where the generated `pub`
//! items are not exported, so the ones a test does not touch would otherwise
//! be reported unused.

mod views_common;

#[allow(dead_code)]
mod sample {
    include!("golden/views_sample.rs");
}

#[allow(dead_code)]
mod fix44 {
    include!("golden/views_fix44_order.rs");
}

#[allow(dead_code)]
mod fixt11 {
    include!("golden/views_fixt11.rs");
}

use ironfix_core::error::{DecodeError, EncodeError};
use ironfix_core::message::RawMessage;
use ironfix_dictionary::{Dictionary, GroupError, GroupSet, GroupSpec, MessageLayout, Validator};
use ironfix_tagvalue::{Decoder, Encoder};
use rust_decimal::Decimal;
use std::cell::Cell;
use std::collections::HashMap;
use std::fmt::Debug;

const SOH: char = '\x01';

/// Unwraps a `Result` with test context instead of `.unwrap()`.
#[track_caller]
fn ok<T, E: Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what}: {err:?}"),
    }
}

/// Unwraps an `Option` with test context instead of `.unwrap()`.
#[track_caller]
fn some<T>(option: Option<T>, what: &str) -> T {
    match option {
        Some(value) => value,
        None => panic!("{what}: expected a value"),
    }
}

/// Builds a FIX 4.4 frame of type `msg_type` with `body` after a standard
/// header, with a matching BodyLength (9) and a dummy CheckSum (10).
fn frame(msg_type: &str, body: &[&str]) -> Vec<u8> {
    let body: Vec<&[u8]> = body.iter().map(|field| field.as_bytes()).collect();
    frame_bytes(msg_type, &body)
}

/// [`frame`] over raw field bytes, which need not be UTF-8.
fn frame_bytes(msg_type: &str, body: &[&[u8]]) -> Vec<u8> {
    let mut text =
        format!("35={msg_type}{SOH}49=S{SOH}56=T{SOH}34=1{SOH}52=20260712-10:00:00{SOH}")
            .into_bytes();
    for field in body {
        text.extend_from_slice(field);
        text.push(b'\x01');
    }
    let mut frame = format!("8=FIX.4.4{SOH}9={}{SOH}", text.len()).into_bytes();
    frame.extend_from_slice(&text);
    frame.extend_from_slice(b"10=000\x01");
    frame
}

/// Decodes a frame built by [`frame`], without checking its checksum.
#[track_caller]
fn decode(frame: &[u8]) -> RawMessage<'_> {
    let mut decoder = Decoder::new(frame).with_checksum_validation(false);
    ok(decoder.decode(), "test frame decodes")
}

/// The tag=value encoder as the sink of the generated FIX 4.4 writers: plain
/// fields through `put_raw`, LENGTH/DATA pairs through `put_data`, which is
/// the only way the encoder accepts them.
impl fix44::writers::Sink for Encoder {
    fn field(&mut self, tag: u32, value: &[u8]) {
        self.put_raw(tag, value);
    }

    fn data(&mut self, length_tag: u32, data_tag: u32, value: &[u8]) {
        self.put_data(length_tag, data_tag, value);
    }
}

/// The same for the sample writers.
impl sample::writers::Sink for Encoder {
    fn field(&mut self, tag: u32, value: &[u8]) {
        self.put_raw(tag, value);
    }

    fn data(&mut self, length_tag: u32, data_tag: u32, value: &[u8]) {
        self.put_data(length_tag, data_tag, value);
    }
}

/// Encodes a body written by a generated writer behind a FIX 4.4 header.
#[track_caller]
fn encode(msg_type: &str, write: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>) -> Vec<u8> {
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, msg_type);
    encoder.put_str(49, "S");
    encoder.put_str(56, "T");
    encoder.put_uint(34, 1);
    encoder.put_str(52, "20260712-10:00:00");
    ok(write(&mut encoder), "the body writes");
    ok(encoder.finish(), "the frame encodes").to_vec()
}

/// The QuickFIX FIX 4.4 test fixture, the dictionary the FIX 4.4 order
/// golden is generated from (see `views_common::fix44_order_dictionary`).
#[track_caller]
fn fix44_dictionary() -> &'static Dictionary {
    static FIX44: std::sync::OnceLock<Dictionary> = std::sync::OnceLock::new();
    FIX44.get_or_init(views_common::quickfix_fix44)
}

#[test]
fn test_generate_views_matches_the_compiled_golden_files() {
    let regenerate =
        "regenerate with: cargo test -p ironfix-codegen --test regenerate_golden -- --ignored";
    assert!(
        views_common::generate_views_sample() == include_str!("golden/views_sample.rs"),
        "generated views drifted from golden/views_sample.rs; {regenerate}"
    );
    assert!(
        views_common::generate_views_fix44_order() == include_str!("golden/views_fix44_order.rs"),
        "generated views drifted from golden/views_fix44_order.rs; {regenerate}"
    );
    assert!(
        views_common::generate_views_fixt11() == include_str!("golden/views_fixt11.rs"),
        "generated views drifted from golden/views_fixt11.rs; {regenerate}"
    );
}

#[test]
fn test_generate_views_is_deterministic() {
    assert!(views_common::generate_views_sample() == views_common::generate_views_sample());
    assert!(
        views_common::generate_views_fix44_order() == views_common::generate_views_fix44_order()
    );
}

#[test]
fn test_views_goldens_carry_no_allow_and_no_binary_float() {
    for golden in [
        include_str!("golden/views_sample.rs"),
        include_str!("golden/views_fix44_order.rs"),
        include_str!("golden/views_fixt11.rs"),
    ] {
        assert!(!golden.contains("#[allow"));
        // Token-wise, so a variant such as `YieldValueOf32nds` is not a match.
        assert!(
            !golden
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|token| token == "f64" || token == "f32")
        );
        assert!(!golden.contains("//!"), "the file must stay include!-able");
    }
}

/// A FIX 4.4 NewOrderSingle with two parties, the first carrying a nested
/// sub-ID group.
fn fix44_order() -> Vec<u8> {
    frame(
        "D",
        &[
            "11=ORDER-1",
            "1=ACC-1",
            "453=2",
            "448=BROKER-A",
            "447=D",
            "452=1",
            "802=1",
            "523=SUB-1",
            "803=2",
            "448=BROKER-B",
            "447=C",
            "452=3",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:01",
            "38=100",
            "40=2",
            "44=1.2345",
            "18=1 G",
            "59=0",
            "58=hello",
        ],
    )
}

#[test]
fn test_fix44_new_order_single_view_reads_every_field_and_the_nested_group() {
    use fix44::enums::{
        ExecInst, OrdType, PartyIDSource, PartyRole, PartySubIDType, Side, TimeInForce,
    };
    use fix44::views::NewOrderSingleView;

    let bytes = fix44_order();
    let msg = decode(&bytes);
    let order = some(
        NewOrderSingleView::from_message(&msg),
        "a NewOrderSingle view",
    );
    assert_eq!(NewOrderSingleView::MSG_TYPE, "D");
    assert!(std::ptr::eq(order.message(), &msg));

    assert_eq!(ok(order.cl_ord_id(), "ClOrdID"), "ORDER-1");
    assert_eq!(ok(order.account(), "Account"), Some("ACC-1"));
    assert_eq!(ok(order.symbol(), "Symbol"), Some("EURUSD"));
    assert_eq!(ok(order.side(), "Side"), Side::Buy);
    assert_eq!(
        ok(order.transact_time(), "TransactTime"),
        "20260712-10:00:01"
    );
    assert_eq!(
        ok(order.order_qty(), "OrderQty"),
        Some(Decimal::new(100, 0))
    );
    assert_eq!(ok(order.ord_type(), "OrdType"), OrdType::Limit);
    assert_eq!(ok(order.price(), "Price"), Some(Decimal::new(12345, 4)));
    let exec_inst: Vec<ExecInst<'_>> =
        some(ok(order.exec_inst(), "ExecInst"), "ExecInst").collect();
    assert_eq!(exec_inst, vec![ExecInst::NotHeld, ExecInst::AllOrNone]);
    assert_eq!(
        ok(order.time_in_force(), "TimeInForce"),
        Some(TimeInForce::Day)
    );
    assert_eq!(ok(order.text(), "Text"), Some("hello"));
    // Absent optional fields read as None.
    assert_eq!(ok(order.stop_px(), "StopPx"), None);
    assert_eq!(ok(order.no_allocs(), "NoAllocs").map(Iterator::count), None);

    let mut parties = some(ok(order.no_party_ids(), "NoPartyIDs"), "the parties");
    assert_eq!(parties.len(), 2);
    let first = some(parties.next(), "the first party");
    assert_eq!(first.entry().index(), 0);
    assert_eq!(ok(first.party_id(), "PartyID"), "BROKER-A");
    assert_eq!(
        ok(first.party_idsource(), "PartyIDSource"),
        Some(PartyIDSource::Proprietary)
    );
    assert_eq!(
        ok(first.party_role(), "PartyRole"),
        Some(PartyRole::ExecutingFirm)
    );
    let mut sub_ids = some(ok(first.no_party_sub_ids(), "NoPartySubIDs"), "the sub-IDs");
    let sub_id = some(sub_ids.next(), "one sub-ID");
    assert_eq!(ok(sub_id.party_sub_id(), "PartySubID"), "SUB-1");
    assert_eq!(
        ok(sub_id.party_sub_idtype(), "PartySubIDType"),
        Some(PartySubIDType::Person)
    );
    assert!(sub_ids.next().is_none());
    let second = some(parties.next(), "the second party");
    assert_eq!(ok(second.party_id(), "PartyID"), "BROKER-B");
    assert_eq!(
        ok(second.party_idsource(), "PartyIDSource"),
        Some(PartyIDSource::GeneralIdentifier)
    );
    assert_eq!(
        ok(second.party_role(), "PartyRole"),
        Some(PartyRole::ClientId)
    );
    assert!(ok(second.no_party_sub_ids(), "absent NoPartySubIDs").is_none());
    assert!(parties.next().is_none());
}

#[test]
fn test_view_of_another_message_type_is_none() {
    let bytes = frame("0", &[]);
    let msg = decode(&bytes);
    assert!(fix44::views::NewOrderSingleView::from_message(&msg).is_none());
    assert!(fix44::views::HeartbeatView::from_message(&msg).is_some());
}

#[test]
fn test_unknown_enum_value_reads_as_other_and_round_trips() {
    use fix44::enums::{ExecInst, OrdType, Side};
    use fix44::views::NewOrderSingleView;

    let bytes = frame(
        "D",
        &[
            "11=ORDER-1",
            "54=Z",
            "60=20260712-10:00:01",
            "40=Q",
            "18=1 ZZ",
        ],
    );
    let msg = decode(&bytes);
    let order = some(
        NewOrderSingleView::from_message(&msg),
        "a NewOrderSingle view",
    );
    let side = ok(order.side(), "an undeclared Side still reads");
    assert_eq!(side, Side::Other(b"Z"));
    assert_eq!(side.as_bytes(), b"Z");
    assert_eq!(ok(order.ord_type(), "OrdType"), OrdType::Other(b"Q"));
    let tokens: Vec<ExecInst<'_>> = some(ok(order.exec_inst(), "ExecInst"), "ExecInst").collect();
    assert_eq!(tokens, vec![ExecInst::NotHeld, ExecInst::Other(b"ZZ")]);

    // Every declared value round-trips through its wire bytes.
    for side in [Side::Buy, Side::Sell, Side::Cross] {
        assert_eq!(Side::from_bytes(side.as_bytes()), side);
    }
    // Values match on exact bytes.
    assert_eq!(Side::from_bytes(b"01"), Side::Other(b"01"));
}

#[test]
fn test_malformed_enum_value_is_an_error_not_other() {
    use fix44::enums::{EncryptMethod, TimeInForce};
    use fix44::views::{LogonView, NewOrderSingleView};

    // Side(54) and TimeInForce(59) are `char`: two characters are no value
    // of the type, declared or not. Before the grammar check they read as
    // `Other(b"AB")`.
    let bytes = frame(
        "D",
        &[
            "11=ORDER-1",
            "54=AB",
            "60=20260712-10:00:01",
            "40=2",
            "59=AB",
        ],
    );
    let msg = decode(&bytes);
    let order = some(
        NewOrderSingleView::from_message(&msg),
        "a NewOrderSingle view",
    );
    assert!(matches!(
        order.side(),
        Err(DecodeError::InvalidFieldValue { tag: 54, .. })
    ));
    assert!(matches!(
        order.time_in_force(),
        Err(DecodeError::InvalidFieldValue { tag: 59, .. })
    ));
    // A well-formed undeclared value is still `Other`.
    let bytes = frame("D", &["11=ORDER-1", "54=1", "59=Z"]);
    let msg = decode(&bytes);
    let order = some(
        NewOrderSingleView::from_message(&msg),
        "a NewOrderSingle view",
    );
    assert_eq!(
        ok(order.time_in_force(), "TimeInForce"),
        Some(TimeInForce::Other(b"Z"))
    );

    // EncryptMethod(98) is an `int`: `+5` is not one, `7` is (undeclared).
    for (value, expected) in [("98=+5", None), ("98=7", Some(EncryptMethod::Other(b"7")))] {
        let bytes = frame("A", &[value, "108=30"]);
        let msg = decode(&bytes);
        let logon = some(LogonView::from_message(&msg), "a Logon view");
        match expected {
            None => assert!(matches!(
                logon.encrypt_method(),
                Err(DecodeError::InvalidFieldValue { tag: 98, .. })
            )),
            Some(method) => assert_eq!(ok(logon.encrypt_method(), "EncryptMethod"), method),
        }
    }
}

#[test]
fn test_multi_value_field_yields_one_token_each_and_joins_back() {
    use sample::enums::ExecInst;

    let tokens: Vec<ExecInst<'_>> = ExecInst::tokens(b"1 2 G").collect();
    assert_eq!(
        tokens,
        vec![ExecInst::NotHeld, ExecInst::Work, ExecInst::AllOrNone]
    );
    assert_eq!(ExecInst::join(&tokens), b"1 2 G");
    assert_eq!(ExecInst::tokens(b"G").count(), 1);
    assert_eq!(ExecInst::join(&[]), b"");
}

#[test]
fn test_missing_required_field_is_a_typed_error() {
    use fix44::views::NewOrderSingleView;

    let bytes = frame("D", &["1=ACC-1"]);
    let msg = decode(&bytes);
    let order = some(
        NewOrderSingleView::from_message(&msg),
        "a NewOrderSingle view",
    );
    assert_eq!(
        order.cl_ord_id(),
        Err(DecodeError::MissingRequiredField { tag: 11 })
    );
    assert_eq!(
        order.side(),
        Err(DecodeError::MissingRequiredField { tag: 54 })
    );
    assert_eq!(
        order.ord_type(),
        Err(DecodeError::MissingRequiredField { tag: 40 })
    );

    // A required member of a group entry is checked per entry.
    let bytes = frame("D", &["11=ORDER-1", "453=1", "448=BROKER-A", "54=1"]);
    let msg = decode(&bytes);
    let order = some(
        sample::views::NewOrderSingleView::from_message(&msg),
        "a sample NewOrderSingle view",
    );
    let party = some(
        some(ok(order.no_party_ids(), "NoPartyIDs"), "the parties").next(),
        "one party",
    );
    assert_eq!(
        party.party_role(),
        Err(DecodeError::MissingRequiredField { tag: 452 })
    );
}

#[test]
fn test_malformed_values_are_typed_errors() {
    use sample::views::NewOrderSingleView;

    let bytes = frame(
        "D",
        &[
            "11=ORDER-1",
            "54=1",
            "60=20260712-10:00:01",
            "44=1.2.3",
            "38=abc",
            "114=X",
            "5002=XY",
        ],
    );
    let msg = decode(&bytes);
    let order = some(NewOrderSingleView::from_message(&msg), "a sample view");
    assert!(matches!(
        order.price(),
        Err(DecodeError::InvalidFieldValue { tag: 44, .. })
    ));
    assert!(matches!(
        order.order_qty(),
        Err(DecodeError::InvalidFieldValue { tag: 38, .. })
    ));
    assert!(matches!(
        order.locate_reqd(),
        Err(DecodeError::InvalidFieldValue { tag: 114, .. })
    ));
    assert!(matches!(
        order.flag(),
        Err(DecodeError::InvalidFieldValue { tag: 5002, .. })
    ));

    // A ClOrdID that is not UTF-8.
    let bytes = frame_bytes("D", &[b"11=ORDER-\xFF", b"54=1"]);
    let msg = decode(&bytes);
    let order = some(NewOrderSingleView::from_message(&msg), "a sample view");
    assert!(matches!(
        order.cl_ord_id(),
        Err(DecodeError::InvalidUtf8(_))
    ));
}

#[test]
fn test_message_level_accessor_ignores_the_same_tag_inside_a_group() {
    use sample::views::NewOrderSingleView;

    // Text (58) only inside a NoPartyIDs entry: no message-level Text.
    let bytes = frame(
        "D",
        &[
            "11=ORDER-1",
            "453=1",
            "448=BROKER-A",
            "452=1",
            "58=in-group",
            "54=1",
        ],
    );
    let msg = decode(&bytes);
    let order = some(NewOrderSingleView::from_message(&msg), "a sample view");
    assert_eq!(ok(order.text(), "message-level Text"), None);
    let party = some(
        some(ok(order.no_party_ids(), "NoPartyIDs"), "the parties").next(),
        "one party",
    );
    assert_eq!(ok(party.text(), "entry Text"), Some("in-group"));

    // The same tag after the group's run is the message-level one.
    let bytes = frame(
        "D",
        &[
            "11=ORDER-1",
            "453=1",
            "448=BROKER-A",
            "452=1",
            "58=in-group",
            "54=1",
            "58=top",
        ],
    );
    let msg = decode(&bytes);
    let order = some(NewOrderSingleView::from_message(&msg), "a sample view");
    assert_eq!(ok(order.text(), "message-level Text"), Some("top"));
}

#[test]
fn test_malformed_group_is_a_typed_error() {
    use sample::views::NewOrderSingleView;

    let bytes = frame(
        "D",
        &["11=ORDER-1", "453=2", "448=BROKER-A", "452=1", "54=1"],
    );
    let msg = decode(&bytes);
    let order = some(NewOrderSingleView::from_message(&msg), "a sample view");
    assert!(matches!(
        order.no_party_ids(),
        Err(GroupError::CountMismatch {
            count_tag: 453,
            declared: 2,
            actual: 1,
        })
    ));
}

#[test]
fn test_fix44_writer_output_decodes_and_validates() {
    use fix44::enums::{ExecInst, OrdType, PartyIDSource, PartyRole, PartySubIDType, Side};
    use fix44::writers::{
        NewOrderSingleFields, PartiesNoPartyIDsFields, PtysSubGrpNoPartySubIDsFields,
    };

    let sub_ids = [PtysSubGrpNoPartySubIDsFields {
        party_sub_id: Some("SUB-1"),
        party_sub_idtype: Some(PartySubIDType::Person),
    }];
    let parties = [
        PartiesNoPartyIDsFields {
            party_id: Some("BROKER-A"),
            party_idsource: Some(PartyIDSource::Proprietary),
            party_role: Some(PartyRole::ExecutingFirm),
            no_party_sub_ids: &sub_ids,
        },
        PartiesNoPartyIDsFields {
            party_id: Some("BROKER-B"),
            party_role: Some(PartyRole::ClientId),
            ..PartiesNoPartyIDsFields::default()
        },
    ];
    let exec_inst = [ExecInst::NotHeld, ExecInst::AllOrNone];
    let order = NewOrderSingleFields {
        cl_ord_id: Some("ORDER-1"),
        side: Some(Side::Buy),
        transact_time: Some("20260712-10:00:01"),
        symbol: Some("EURUSD"),
        order_qty: Some(Decimal::new(100, 0)),
        ord_type: Some(OrdType::Limit),
        price: Some(Decimal::new(12345, 4)),
        exec_inst: &exec_inst,
        no_party_ids: &parties,
        ..NewOrderSingleFields::default()
    };

    let bytes = encode("D", |encoder| order.write(encoder));
    let mut decoder = Decoder::new(&bytes);
    let msg = ok(
        decoder.decode(),
        "the written frame decodes with its checksum",
    );
    assert_eq!(
        Validator::new(fix44_dictionary()).validate(&msg),
        Ok(()),
        "the written NewOrderSingle conforms to the FIX 4.4 dictionary"
    );

    // Each entry opens with its delimiter.
    let tags: Vec<u32> = msg.fields().map(|field| field.tag).collect();
    let after = |count_tag: u32| {
        tags.iter()
            .position(|tag| *tag == count_tag)
            .and_then(|index| tags.get(index + 1))
            .copied()
    };
    assert_eq!(after(453), Some(448));
    assert_eq!(after(802), Some(523));

    // And reads back through the view.
    let view = some(
        fix44::views::NewOrderSingleView::from_message(&msg),
        "a NewOrderSingle view",
    );
    assert_eq!(ok(view.cl_ord_id(), "ClOrdID"), "ORDER-1");
    assert_eq!(ok(view.price(), "Price"), Some(Decimal::new(12345, 4)));
    assert_eq!(ok(view.order_qty(), "OrderQty"), Some(Decimal::new(100, 0)));
    let read: Vec<ExecInst<'_>> = some(ok(view.exec_inst(), "ExecInst"), "ExecInst").collect();
    assert_eq!(read, exec_inst);
    let ids: Vec<&str> = some(ok(view.no_party_ids(), "NoPartyIDs"), "the parties")
        .map(|party| ok(party.party_id(), "PartyID"))
        .collect();
    assert_eq!(ids, vec!["BROKER-A", "BROKER-B"]);
}

#[test]
fn test_sample_writer_output_validates_and_keeps_every_shape() {
    use sample::enums::{ExecInst, SecurityType, Side};
    use sample::writers::{
        NewOrderSingleFields, NewOrderSingleNoAllocsFields, PartiesNoPartyIDsFields,
    };

    let allocs = [NewOrderSingleNoAllocsFields {
        alloc_account: Some("ALLOC-1"),
        alloc_qty: Some(Decimal::new(5, 1)),
    }];
    let parties = [PartiesNoPartyIDsFields {
        party_id: Some("BROKER-A"),
        party_role: Some(7),
        text: Some("in-group"),
        ..PartiesNoPartyIDsFields::default()
    }];
    let order = NewOrderSingleFields {
        cl_ord_id: Some("ORDER-1"),
        cl_ord_id_12: Some("ORDER-1B"),
        side: Some(Side::Sell),
        transact_time: Some("20260712-10:00:01"),
        price: Some(Decimal::new(-15, 1)),
        exec_inst: &[ExecInst::Work],
        locate_reqd: Some(true),
        raw_data: Some(&b"a=\x01b"[..]),
        r#yield: Some(Decimal::new(25, 3)),
        text: Some("top"),
        field_to_venue: Some("VENUE"),
        get_5001: Some("GET"),
        flag: Some('F'),
        symbol: Some("EURUSD"),
        security_type: Some(SecurityType::Quoted),
        no_allocs: &allocs,
        no_party_ids: &parties,
        ..NewOrderSingleFields::default()
    };
    let bytes = encode("D", |encoder| order.write(encoder));
    let mut decoder = Decoder::new(&bytes);
    let msg = ok(decoder.decode(), "the written frame decodes");
    let dict = views_common::views_sample_dictionary();
    assert_eq!(Validator::new(&dict).validate(&msg), Ok(()));

    let view = some(
        sample::views::NewOrderSingleView::from_message(&msg),
        "a sample view",
    );
    assert_eq!(ok(view.cl_ord_id_12(), "ClOrdId"), Some("ORDER-1B"));
    assert_eq!(ok(view.price(), "Price"), Some(Decimal::new(-15, 1)));
    assert_eq!(ok(view.locate_reqd(), "LocateReqd"), Some(true));
    assert_eq!(view.raw_data(), Some(&b"a=\x01b"[..]));
    assert_eq!(ok(view.raw_data_length(), "RawDataLength"), Some(4));
    assert_eq!(ok(view.r#yield(), "Yield"), Some(Decimal::new(25, 3)));
    assert_eq!(ok(view.text(), "Text"), Some("top"));
    assert_eq!(ok(view.field_to_venue(), "ToVenue"), Some("VENUE"));
    assert_eq!(ok(view.get_5001(), "Get"), Some("GET"));
    assert_eq!(ok(view.flag(), "Flag"), Some('F'));
    assert_eq!(
        ok(view.security_type(), "SecurityType"),
        Some(SecurityType::Quoted)
    );
    let alloc = some(
        some(ok(view.no_allocs(), "NoAllocs"), "the allocations").next(),
        "one allocation",
    );
    assert_eq!(ok(alloc.alloc_account(), "AllocAccount"), "ALLOC-1");
    assert_eq!(ok(alloc.alloc_qty(), "AllocQty"), Some(Decimal::new(5, 1)));
    let party = some(
        some(ok(view.no_party_ids(), "NoPartyIDs"), "the parties").next(),
        "one party",
    );
    assert_eq!(ok(party.party_role(), "PartyRole"), 7);
    assert_eq!(ok(party.text(), "entry Text"), Some("in-group"));
}

#[test]
fn test_writer_refuses_missing_required_members_before_writing() {
    use fix44::writers::{NewOrderSingleFields, PartiesNoPartyIDsFields};

    let calls = Cell::new(0usize);
    let mut counting = |_tag: u32, _value: &[u8]| calls.set(calls.get() + 1);

    let order = NewOrderSingleFields {
        side: Some(fix44::enums::Side::Buy),
        ..NewOrderSingleFields::default()
    };
    assert_eq!(
        order.write(&mut counting),
        Err(EncodeError::MissingRequiredField { tag: 11 })
    );

    // An entry without its delimiter, behind an otherwise complete order.
    let parties = [PartiesNoPartyIDsFields::default()];
    let order = NewOrderSingleFields {
        cl_ord_id: Some("ORDER-1"),
        side: Some(fix44::enums::Side::Buy),
        transact_time: Some("20260712-10:00:01"),
        ord_type: Some(fix44::enums::OrdType::Market),
        no_party_ids: &parties,
        ..NewOrderSingleFields::default()
    };
    assert_eq!(
        order.write(&mut counting),
        Err(EncodeError::MissingRequiredField { tag: 448 })
    );
    assert_eq!(calls.get(), 0, "nothing is written when a check fails");

    // A char that is not ASCII.
    let sample_order = sample::writers::NewOrderSingleFields {
        cl_ord_id: Some("ORDER-1"),
        side: Some(sample::enums::Side::Buy),
        transact_time: Some("20260712-10:00:01"),
        symbol: Some("EURUSD"),
        flag: Some('\u{e9}'),
        ..sample::writers::NewOrderSingleFields::default()
    };
    assert!(matches!(
        sample_order.write(&mut counting),
        Err(EncodeError::InvalidFieldValue { tag: 5002, .. })
    ));
    assert_eq!(calls.get(), 0, "nothing is written when a check fails");

    // A dynamically typed sink is accepted as well.
    let mut boxed: Box<DynSink<'_>> = Box::new(|_tag, _value| calls.set(calls.get() + 1));
    let heartbeat = fix44::writers::HeartbeatFields {
        test_req_id: Some("PING"),
    };
    assert_eq!(heartbeat.write(&mut *boxed), Ok(()));
    drop(boxed);
    assert_eq!(calls.get(), 1);
}

/// A closure sink behind a trait object.
type DynSink<'c> = dyn FnMut(u32, &[u8]) + 'c;

#[test]
fn test_closure_sink_receives_a_data_pair_as_length_then_data() {
    let order = sample::writers::NewOrderSingleFields {
        cl_ord_id: Some("ORDER-1"),
        side: Some(sample::enums::Side::Buy),
        transact_time: Some("20260712-10:00:01"),
        symbol: Some("EURUSD"),
        raw_data: Some(&b"a\x01b"[..]),
        ..sample::writers::NewOrderSingleFields::default()
    };
    let mut fields: Vec<(u32, Vec<u8>)> = Vec::new();
    ok(
        order.write(&mut |tag: u32, value: &[u8]| fields.push((tag, value.to_vec()))),
        "the order writes to a closure",
    );
    let length = some(
        fields.iter().position(|(tag, _)| *tag == 95),
        "the derived RawDataLength",
    );
    assert_eq!(fields.get(length), Some(&(95, b"3".to_vec())));
    assert_eq!(fields.get(length + 1), Some(&(96, b"a\x01b".to_vec())));
    let tags: Vec<u32> = fields.iter().map(|(tag, _)| *tag).collect();
    assert_eq!(tags.first(), Some(&11), "XML order: ClOrdID first");
}

#[test]
fn test_message_without_fields_writes_nothing() {
    let calls = Cell::new(0usize);
    let mut counting = |_tag: u32, _value: &[u8]| calls.set(calls.get() + 1);
    assert_eq!(
        sample::writers::HeartbeatFields::default().write(&mut counting),
        Ok(())
    );
    assert_eq!(calls.get(), 0);
}

/// Asserts two group sets describe the same groups, recursively.
#[track_caller]
fn assert_same_set(generated: GroupSet<'_>, layout: GroupSet<'_>, context: &str) {
    let generated: Vec<GroupSpec<'_>> = generated.iter().collect();
    let layout: Vec<GroupSpec<'_>> = layout.iter().collect();
    assert_eq!(generated.len(), layout.len(), "{context}: group count");
    for (left, right) in generated.into_iter().zip(layout) {
        let context = format!("{context} > {}", right.count_tag());
        assert_eq!(left.count_tag(), right.count_tag(), "{context}: count tag");
        assert_eq!(
            left.delimiter_tag(),
            right.delimiter_tag(),
            "{context}: delimiter"
        );
        assert_eq!(left.members(), right.members(), "{context}: members");
        assert_same_set(left.nested_groups(), right.nested_groups(), &context);
    }
}

#[test]
fn test_static_layouts_agree_with_the_dictionary_layout() {
    let fix44_dict = fix44_dictionary();
    for (msg_type, generated) in [
        ("0", fix44::layouts::HEARTBEAT),
        ("A", fix44::layouts::LOGON),
        ("D", fix44::layouts::NEW_ORDER_SINGLE),
    ] {
        let layout = ok(MessageLayout::new(fix44_dict, msg_type), "FIX 4.4 layout");
        assert_same_set(generated, layout.groups(), &format!("FIX 4.4 {msg_type}"));
    }
    let sample_dict = views_common::views_sample_dictionary();
    for (msg_type, generated) in [
        ("0", sample::layouts::HEARTBEAT),
        ("8", sample::layouts::EXECUTION_REPORT),
        ("D", sample::layouts::NEW_ORDER_SINGLE),
    ] {
        let layout = ok(MessageLayout::new(&sample_dict, msg_type), "sample layout");
        assert_same_set(generated, layout.groups(), &format!("sample {msg_type}"));
    }
    let fixt11_dict = ok(
        Dictionary::fixt11(),
        "the embedded FIXT 1.1 dictionary loads",
    );
    let layout = ok(
        MessageLayout::new(fixt11_dict, "A"),
        "FIXT 1.1 Logon layout",
    );
    assert_same_set(fixt11::layouts::LOGON, layout.groups(), "FIXT 1.1 A");
}

#[test]
fn test_component_group_has_one_type_shared_by_its_messages() {
    use sample::views::{ExecutionReportView, NewOrderSingleView, PartiesNoPartyIDsView};

    let golden = include_str!("golden/views_sample.rs");
    assert_eq!(
        golden.matches("pub struct PartiesNoPartyIDsView<").count(),
        1
    );
    assert_eq!(
        golden
            .matches("pub struct PartiesNoPartyIDsFields<")
            .count(),
        1
    );
    assert_eq!(golden.matches("pub const PARTIES_NO_PARTY_IDS:").count(), 1);

    /// Reads the PartyID of every party, whichever message they came from:
    /// one type for both.
    fn party_ids<'m, 'a: 'm>(
        parties: impl Iterator<Item = PartiesNoPartyIDsView<'m, 'a>>,
    ) -> Vec<&'a str> {
        parties
            .map(|party| ok(party.party_id(), "PartyID"))
            .collect()
    }

    let order_bytes = frame("D", &["11=O", "453=1", "448=FROM-ORDER", "452=1", "54=1"]);
    let order_msg = decode(&order_bytes);
    let order = some(
        NewOrderSingleView::from_message(&order_msg),
        "an order view",
    );
    let report_bytes = frame("8", &["11=O", "453=1", "448=FROM-REPORT", "452=1", "54=1"]);
    let report_msg = decode(&report_bytes);
    let report = some(
        ExecutionReportView::from_message(&report_msg),
        "a report view",
    );
    let from_order = some(ok(order.no_party_ids(), "order parties"), "parties");
    let from_report = some(ok(report.no_party_ids(), "report parties"), "parties");
    assert_eq!(party_ids(from_order), vec!["FROM-ORDER"]);
    assert_eq!(party_ids(from_report), vec!["FROM-REPORT"]);
}

#[test]
fn test_enum_variant_naming_edge_cases() {
    use sample::enums::{PartyIDSource, SecurityType};

    // `(wire value, variant)`: an empty description, the fallback name, a
    // keyword, a leading digit, a name ending with the enumeration's, two
    // descriptions folding onto one name, and escaped wire values.
    let cases: [(&[u8], SecurityType<'_>); 10] = [
        (b"?", SecurityType::Value),
        (b"1D", SecurityType::Value1Day),
        (b"CS", SecurityType::CommonStock),
        (b"EURIBOR", SecurityType::Euribor),
        (b"Euribor", SecurityType::EuriborEuribor),
        (b"NONE", SecurityType::NoSecurityTypeNone),
        (b"OTHER", SecurityType::OtherOther),
        (b"Q\"\\", SecurityType::Quoted),
        (b"SELF", SecurityType::SelfSelf),
        ("\u{c9}".as_bytes(), SecurityType::EAcute),
    ];
    for (value, expected) in cases {
        assert_eq!(SecurityType::from_bytes(value), expected);
        assert_eq!(expected.as_bytes(), value);
    }
    assert_eq!(PartyIDSource::from_bytes(b"9"), PartyIDSource::Other9);
    assert_eq!(PartyIDSource::from_bytes(b"Z"), PartyIDSource::Other(b"Z"));
}

#[test]
fn test_generated_debug_never_prints_field_values() {
    let logon = fix44::writers::LogonFields {
        username: Some("user"),
        password: Some("hunter2"),
        ..fix44::writers::LogonFields::default()
    };
    let printed = format!("{logon:?}");
    assert!(!printed.contains("hunter2"), "{printed}");
    assert!(printed.contains("LogonFields"), "{printed}");

    let bytes = frame("A", &["98=0", "108=30", "553=user", "554=hunter2"]);
    let msg = decode(&bytes);
    let view = some(fix44::views::LogonView::from_message(&msg), "a Logon view");
    assert_eq!(ok(view.password(), "Password"), Some("hunter2"));
    assert_eq!(ok(view.heart_bt_int(), "HeartBtInt"), 30);
    let printed = format!("{view:?}");
    assert!(!printed.contains("hunter2"), "{printed}");
}

#[test]
fn test_fixt11_views_read_a_logon() {
    use fixt11::views::LogonView;

    let bytes = frame("A", &["98=0", "108=30", "1137=9"]);
    let msg = decode(&bytes);
    let logon = some(LogonView::from_message(&msg), "a FIXT 1.1 Logon view");
    assert_eq!(ok(logon.heart_bt_int(), "HeartBtInt"), 30);
    assert_eq!(
        ok(logon.encrypt_method(), "EncryptMethod"),
        fixt11::enums::EncryptMethod::None0
    );
}

#[test]
fn test_length_delimited_group_writes_its_pair_first_and_reads_back() {
    use sample::writers::{TypeSamplerFields, TypeSamplerNoDocsFields};

    let docs = [
        TypeSamplerNoDocsFields {
            encoded_text: Some(&b"a\x01b"[..]),
            doc_name: Some("first"),
        },
        TypeSamplerNoDocsFields {
            encoded_text: Some(&b"xyz!"[..]),
            doc_name: None,
        },
    ];
    let sampler = TypeSamplerFields {
        no_docs: &docs,
        ..TypeSamplerFields::default()
    };
    let bytes = encode("U1", |encoder| sampler.write(encoder));
    let mut decoder = Decoder::new(&bytes);
    let msg = ok(decoder.decode(), "the written frame decodes");
    let dict = views_common::views_sample_dictionary();
    assert_eq!(Validator::new(&dict).validate(&msg), Ok(()));

    // The length opens each entry: it is the delimiter.
    let tags: Vec<u32> = msg.fields().map(|field| field.tag).collect();
    let start = some(tags.iter().position(|tag| *tag == 5020), "NoDocs");
    assert_eq!(
        tags.get(start..),
        Some(&[5020, 354, 355, 5023, 354, 355][..])
    );

    let view = some(
        sample::views::TypeSamplerView::from_message(&msg),
        "a TypeSampler view",
    );
    let read: Vec<(u64, &[u8], Option<&str>)> = some(ok(view.no_docs(), "NoDocs"), "the docs")
        .map(|doc| {
            (
                ok(doc.encoded_text_len(), "EncodedTextLen"),
                ok(doc.encoded_text(), "EncodedText"),
                ok(doc.doc_name(), "DocName"),
            )
        })
        .collect();
    assert_eq!(
        read,
        vec![(3, &b"a\x01b"[..], Some("first")), (4, &b"xyz!"[..], None)]
    );

    // The data opens the entry with its length, so it is required.
    let missing = [TypeSamplerNoDocsFields {
        encoded_text: None,
        doc_name: Some("orphan"),
    }];
    let sampler = TypeSamplerFields {
        no_docs: &missing,
        ..TypeSamplerFields::default()
    };
    let mut ignore = |_tag: u32, _value: &[u8]| {};
    assert_eq!(
        sampler.write(&mut ignore),
        Err(EncodeError::MissingRequiredField { tag: 355 })
    );
}

#[test]
fn test_writer_writes_a_required_group_with_no_entries_as_count_zero() {
    // A required group requires its count field, not an entry: FIX allows
    // `NoXxx=0` (FIX 4.4 NewOrderList with `73=0` validates), so a required
    // group with no entries is written with count 0, never left out.
    let sampler = sample::writers::TypeSamplerFields {
        expire_seconds: Some(5),
        ..sample::writers::TypeSamplerFields::default()
    };
    let bytes = encode("U1", |encoder| sampler.write(encoder));
    assert!(
        bytes.windows(8).any(|window| window == b"\x015020=0\x01"),
        "the count is written"
    );
    let mut decoder = Decoder::new(&bytes);
    let msg = ok(decoder.decode(), "the written frame decodes");
    let dict = views_common::views_sample_dictionary();
    assert_eq!(Validator::new(&dict).validate(&msg), Ok(()));
    let view = some(
        sample::views::TypeSamplerView::from_message(&msg),
        "a TypeSampler view",
    );
    assert_eq!(
        ok(view.no_docs(), "NoDocs").map(|entries| entries.count()),
        Some(0)
    );

    // An optional group with no entries is still left out.
    let order = sample::writers::NewOrderSingleFields {
        cl_ord_id: Some("ORDER-1"),
        side: Some(sample::enums::Side::Buy),
        transact_time: Some("20260712-10:00:01"),
        symbol: Some("EURUSD"),
        ..sample::writers::NewOrderSingleFields::default()
    };
    let bytes = encode("D", |encoder| order.write(encoder));
    assert!(!bytes.windows(5).any(|window| window == b"\x01453="));
}

#[test]
fn test_prelude_variant_names_are_never_taken() {
    use sample::enums::Mode;

    let cases: [(&[u8], Mode<'_>); 4] = [
        (b"0", Mode::None0),
        (b"1", Mode::Some1),
        (b"2", Mode::Ok2),
        (b"3", Mode::Err3),
    ];
    for (value, expected) in cases {
        assert_eq!(Mode::from_bytes(value), expected);
    }
    let golden = include_str!("golden/views_sample.rs");
    for name in ["None,", "Some,", "Ok,", "Err,"] {
        assert!(!golden.contains(&format!("        {name}\n")), "{name}");
    }
}

/// Decodes a TypeSampler (`U1`) frame carrying `body`.
#[track_caller]
fn sampler_frame(body: &[&str]) -> Vec<u8> {
    frame("U1", body)
}

/// Asserts that reading field `tag` of a TypeSampler carrying `field` is an
/// invalid-value error.
#[track_caller]
fn assert_sampler_rejects(field: &str, tag: u32) {
    let bytes = sampler_frame(&[field]);
    let msg = decode(&bytes);
    let view = some(
        sample::views::TypeSamplerView::from_message(&msg),
        "a TypeSampler view",
    );
    let read: Result<(), DecodeError> = match tag {
        44 => view.price().map(|_| ()),
        60 => view.transact_time().map(|_| ()),
        5010 => view.sample_time().map(|_| ()),
        5011 => view.sample_date().map(|_| ()),
        75 => view.trade_date().map(|_| ()),
        200 => view.maturity_month_year().map(|_| ()),
        205 => view.maturity_day().map(|_| ()),
        421 => view.country().map(|_| ()),
        15 => view.currency().map(|_| ()),
        5012 => view.expire_seconds().map(|_| ()),
        5013 => view.labels().map(|_| ()),
        5014 => view.flags().map(|_| ()),
        _ => panic!("no accessor for tag {tag}"),
    };
    assert!(
        matches!(read, Err(DecodeError::InvalidFieldValue { tag: found, .. }) if found == tag),
        "{field}: {read:?}"
    );
}

#[test]
fn test_views_refuse_what_the_validator_refuses() {
    // Decimals: no exponent, sign or digit separator, and never rounded.
    for field in [
        "44=1e5",
        "44=+1.5",
        "44=1_000.5",
        "44=0.00000000000000000000000000001",
        "44=79228162514264337593543950336",
    ] {
        assert_sampler_rejects(field, 44);
    }
    // Integers: no plus sign; a day of the month is 1 to 31.
    assert_sampler_rejects("5012=+5", 5012);
    for field in ["205=+5", "205=0", "205=32"] {
        assert_sampler_rejects(field, 205);
    }
    // Dates, times, month-years, countries and currencies.
    for (field, tag) in [
        ("60=20260712-10:00", 60),
        ("5010=10:00", 5010),
        ("5011=2026071", 5011),
        ("75=2026-07-12", 75),
        ("200=2026", 200),
        ("421=USA", 421),
        ("15=EU", 15),
    ] {
        assert_sampler_rejects(field, tag);
    }
    // Multi-value fields: no empty token; one character per char token.
    for (field, tag) in [
        ("5013=a  b", 5013),
        ("5013=a ", 5013),
        ("5014=A  B", 5014),
        ("5014=AB", 5014),
    ] {
        assert_sampler_rejects(field, tag);
    }
}

#[test]
fn test_views_read_well_formed_typed_values() {
    use sample::enums::Flags;

    let bytes = sampler_frame(&[
        "60=20260712-10:00:00.123",
        "5010=10:00:00",
        "5011=20260712",
        "75=20260712",
        "200=202607w2",
        "205=31",
        "421=US",
        "15=EUR",
        "44=-1.25",
        "5012=-5",
        "5013=a b",
        "5014=A B Z",
        "5020=0",
    ]);
    let msg = decode(&bytes);
    let view = some(
        sample::views::TypeSamplerView::from_message(&msg),
        "a TypeSampler view",
    );
    assert_eq!(
        ok(view.transact_time(), "TransactTime"),
        Some("20260712-10:00:00.123")
    );
    assert_eq!(ok(view.sample_time(), "SampleTime"), Some("10:00:00"));
    assert_eq!(ok(view.sample_date(), "SampleDate"), Some("20260712"));
    assert_eq!(ok(view.trade_date(), "TradeDate"), Some("20260712"));
    assert_eq!(
        ok(view.maturity_month_year(), "MaturityMonthYear"),
        Some("202607w2")
    );
    assert_eq!(ok(view.maturity_day(), "MaturityDay"), Some(31));
    assert_eq!(ok(view.country(), "Country"), Some("US"));
    assert_eq!(ok(view.currency(), "Currency"), Some("EUR"));
    assert_eq!(ok(view.price(), "Price"), Some(Decimal::new(-125, 2)));
    assert_eq!(ok(view.expire_seconds(), "ExpireSeconds"), Some(-5));
    assert_eq!(ok(view.labels(), "Labels"), Some("a b"));
    let flags: Vec<Flags<'_>> = some(ok(view.flags(), "Flags"), "Flags").collect();
    assert_eq!(flags, vec![Flags::Alpha, Flags::Bravo, Flags::Other(b"Z")]);
}

#[test]
fn test_writer_refuses_malformed_values_before_writing() {
    use sample::enums::{Flags, Side};
    use sample::writers::NewOrderSingleFields;

    let calls = Cell::new(0usize);
    let mut counting = |_tag: u32, _value: &[u8]| calls.set(calls.get() + 1);
    let complete = NewOrderSingleFields {
        cl_ord_id: Some("ORDER-1"),
        side: Some(Side::Buy),
        transact_time: Some("20260712-10:00:01"),
        symbol: Some("EURUSD"),
        ..NewOrderSingleFields::default()
    };
    let refused = |fields: NewOrderSingleFields<'_>, tag: u32, what: &str| {
        let mut sink = |_tag: u32, _value: &[u8]| calls.set(calls.get() + 1);
        assert!(
            matches!(
                fields.write(&mut sink),
                Err(EncodeError::InvalidFieldValue { tag: found, .. }) if found == tag
            ),
            "{what}"
        );
    };
    refused(
        NewOrderSingleFields {
            account: Some(""),
            ..complete
        },
        1,
        "an empty value",
    );
    refused(
        NewOrderSingleFields {
            text: Some("a\x01b"),
            ..complete
        },
        58,
        "SOH in a text value",
    );
    refused(
        NewOrderSingleFields {
            side: Some(Side::Other(b"")),
            ..complete
        },
        54,
        "an empty enumeration value",
    );
    refused(
        NewOrderSingleFields {
            side: Some(Side::Other(b"1\x012")),
            ..complete
        },
        54,
        "SOH in an enumeration value",
    );
    refused(
        NewOrderSingleFields {
            flag: Some('\u{1}'),
            ..complete
        },
        5002,
        "a control character",
    );
    refused(
        NewOrderSingleFields {
            raw_data: Some(&b""[..]),
            ..complete
        },
        96,
        "empty data",
    );
    let sampler = |flags: &[Flags<'_>]| {
        let docs = [sample::writers::TypeSamplerNoDocsFields {
            encoded_text: Some(&b"x"[..]),
            doc_name: None,
        }];
        let fields = sample::writers::TypeSamplerFields {
            flags,
            no_docs: &docs,
            ..sample::writers::TypeSamplerFields::default()
        };
        let mut sink = |_tag: u32, _value: &[u8]| calls.set(calls.get() + 1);
        fields.write(&mut sink)
    };
    for (flags, what) in [
        (&[Flags::Alpha, Flags::Other(b"")][..], "an empty token"),
        (&[Flags::Other(b"A B")][..], "a token with a space"),
        (&[Flags::Other(b"\x01")][..], "a token with SOH"),
    ] {
        assert!(
            matches!(
                sampler(flags),
                Err(EncodeError::InvalidFieldValue { tag: 5014, .. })
            ),
            "{what}"
        );
    }
    assert_eq!(calls.get(), 0, "nothing is written when a check fails");
    // Data may carry SOH: it is written with its length.
    assert_eq!(
        NewOrderSingleFields {
            raw_data: Some(&b"\x01"[..]),
            ..complete
        }
        .write(&mut counting),
        Ok(())
    );
}

/// Every numeric tag written by the statements of `code` that start with
/// `call` (for example `sink.field(`), and the tag after it when the call
/// carries two (`sink.data(`).
fn written_tags(code: &str, call: &str, pairs: bool) -> Vec<(u32, u32)> {
    let mut found = Vec::new();
    for (index, _) in code.match_indices(call) {
        let rest = code.get(index + call.len()..).unwrap_or("");
        let mut numbers = rest.split([',', ')']).map(str::trim).map(str::parse::<u32>);
        let Some(Ok(first)) = numbers.next() else {
            // A helper's own body (`sink.field(tag, ...)`), not a statement.
            continue;
        };
        if pairs {
            if let Some(Ok(second)) = numbers.next() {
                found.push((first, second));
            }
        } else {
            found.push((first, 0));
        }
    }
    found
}

#[test]
fn test_generated_writers_agree_with_the_encoder_on_every_embedded_dictionary() {
    // The tag=value encoder frames LENGTH/DATA pairs from its own table
    // (FIX spec pairs, dictionary-free); the writers pair fields from the
    // dictionary. Every pair a writer emits must be one `put_data` accepts,
    // and every other field one `put_raw` accepts.
    for (what, dict) in [
        ("FIX 4.2", Dictionary::fix42()),
        ("FIX 4.4", Dictionary::fix44()),
        ("FIXT 1.1", Dictionary::fixt11()),
        ("FIX 5.0 SP2", Dictionary::fix50sp2()),
    ] {
        let dict = ok(dict, what);
        let code = ok(
            ironfix_codegen::CodeGenerator::new().generate_views(dict),
            what,
        );
        let pairs = written_tags(&code, "sink.data(", true);
        let plain: Vec<(u32, u32)> = written_tags(&code, "sink.field(", false)
            .into_iter()
            .chain(written_tags(&code, "put_display(sink, ", false))
            .collect();
        assert!(
            !pairs.is_empty() || what == "FIXT 1.1",
            "{what}: pairs found"
        );
        assert!(!plain.is_empty(), "{what}: plain fields found");
        for (length_tag, data_tag) in pairs {
            let mut encoder = Encoder::new("FIX.4.4");
            assert_eq!(
                encoder.try_put_data(length_tag, data_tag, b"x"),
                Ok(()),
                "{what}: pair {length_tag}/{data_tag}"
            );
        }
        for (tag, _) in plain {
            let mut encoder = Encoder::new("FIX.4.4");
            assert_eq!(
                encoder.try_put_raw(tag, b"1"),
                Ok(()),
                "{what}: plain field {tag}"
            );
        }
    }
}

/// A group table parsed back from a generated `layouts` module.
#[derive(Debug)]
struct ParsedSpec {
    count_tag: u32,
    delimiter_tag: u32,
    members: Vec<u32>,
    nested: Vec<String>,
}

/// Splits `a, b, c` into its trimmed, non-empty items.
fn items(list: &str) -> Vec<&str> {
    list.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect()
}

/// Every group table of a `layouts` module by constant name, and every
/// message's top-level group constants by MsgType.
type ParsedLayouts = (HashMap<String, ParsedSpec>, Vec<ParsedSet>);

/// A message's top-level set parsed back: its MsgType, its group constants
/// and its level tags.
type ParsedSet = (String, Vec<String>, Vec<u32>);

/// Parses the `layouts` module of generated views.
fn parse_layouts(code: &str) -> ParsedLayouts {
    let mut specs = HashMap::new();
    let mut messages = Vec::new();
    let mut msg_type: Option<String> = None;
    for text in code.lines() {
        let text = text.trim();
        if let Some(rest) = text.strip_prefix("/// Groups that may open at the top level of ") {
            msg_type = rest
                .split_once("(MsgType=")
                .and_then(|(_, tail)| tail.split_once(')'))
                .map(|(value, _)| value.to_string());
        }
        let Some(rest) = text.strip_prefix("pub const ") else {
            continue;
        };
        let Some((name, rest)) = rest.split_once(':') else {
            continue;
        };
        if let Some(arguments) = rest
            .split_once("GroupSpec::new(")
            .and_then(|(_, tail)| tail.rsplit_once(") {"))
            .map(|(arguments, _)| arguments)
        {
            let (scalars, lists) = some(arguments.split_once("&["), "a member list");
            let numbers: Vec<u32> = items(scalars)
                .into_iter()
                .map(|item| ok(item.parse::<u32>(), "a tag"))
                .collect();
            let (members, nested) = some(lists.split_once("], &["), "a nested list");
            let nested = nested.trim_end_matches(']');
            specs.insert(
                name.to_string(),
                ParsedSpec {
                    count_tag: some(numbers.first().copied(), "a count tag"),
                    delimiter_tag: some(numbers.get(1).copied(), "a delimiter"),
                    members: items(members)
                        .into_iter()
                        .map(|item| ok(item.parse::<u32>(), "a member"))
                        .collect(),
                    nested: items(nested).into_iter().map(ToString::to_string).collect(),
                },
            );
        } else if let Some(arguments) = rest
            .split_once("GroupSet::with_level_tags(&[")
            .and_then(|(_, tail)| tail.rsplit_once("]) {"))
            .map(|(arguments, _)| arguments)
        {
            let msg_type = some(msg_type.take(), "the set's MsgType");
            let (groups, tags) = some(arguments.split_once("], &["), "a level-tag list");
            messages.push((
                msg_type,
                items(groups).into_iter().map(ToString::to_string).collect(),
                items(tags)
                    .into_iter()
                    .map(|item| ok(item.parse::<u32>(), "a level tag"))
                    .collect(),
            ));
        }
    }
    (specs, messages)
}

/// Asserts the parsed tables named `names` describe `layout`, recursively.
#[track_caller]
fn assert_parsed_set(
    specs: &HashMap<String, ParsedSpec>,
    names: &[String],
    layout: GroupSet<'_>,
    context: &str,
) {
    let groups: Vec<GroupSpec<'_>> = layout.iter().collect();
    assert_eq!(names.len(), groups.len(), "{context}: group count");
    for (name, group) in names.iter().zip(groups) {
        let parsed = some(specs.get(name), name);
        let context = format!("{context} > {}", group.count_tag());
        assert_eq!(parsed.count_tag, group.count_tag(), "{context}");
        assert_eq!(parsed.delimiter_tag, group.delimiter_tag(), "{context}");
        assert_eq!(parsed.members.as_slice(), group.members(), "{context}");
        assert_parsed_set(specs, &parsed.nested, group.nested_groups(), &context);
    }
}

#[test]
fn test_every_generated_layout_agrees_with_the_dictionary_layout() {
    // Every message of every embedded dictionary, from the generated text:
    // the compiled goldens cover only a few messages.
    for (what, dict) in [
        ("FIX 4.2", Dictionary::fix42()),
        ("FIX 4.4", Dictionary::fix44()),
        ("FIXT 1.1", Dictionary::fixt11()),
        ("FIX 5.0 SP2", Dictionary::fix50sp2()),
    ] {
        let dict = ok(dict, what);
        let code = ok(
            ironfix_codegen::CodeGenerator::new().generate_views(dict),
            what,
        );
        let (specs, messages) = parse_layouts(&code);
        assert_eq!(
            messages.len(),
            dict.messages().count(),
            "{what}: one set per message"
        );
        for (msg_type, names, level_tags) in messages {
            let layout = ok(MessageLayout::new(dict, &msg_type), "layout");
            assert_eq!(
                level_tags.as_slice(),
                layout.groups().level_tags(),
                "{what} {msg_type}: level tags"
            );
            assert_parsed_set(
                &specs,
                &names,
                layout.groups(),
                &format!("{what} {msg_type}"),
            );
        }
    }
}

#[test]
fn test_writer_keeps_the_xml_order_inside_a_group_entry() {
    // FIX 4.4 PreAllocGrp NoAllocs(78) lists AllocAccount(79),
    // AllocAcctIDSource(661), AllocSettlCurrency(736), IndividualAllocID(467),
    // the NestedParties component (NoNestedPartyIDs 539) and AllocQty(80):
    // the writer follows that order, the component's group in its place.
    use fix44::enums::{OrdType, Side};
    use fix44::writers::{
        NestedPartiesNoNestedPartyIDsFields, NewOrderSingleFields, PreAllocGrpNoAllocsFields,
    };

    let nested = [NestedPartiesNoNestedPartyIDsFields {
        nested_party_id: Some("NESTED-1"),
        nested_party_role: Some(1),
        ..NestedPartiesNoNestedPartyIDsFields::default()
    }];
    let allocs = [PreAllocGrpNoAllocsFields {
        alloc_account: Some("ACC-1"),
        alloc_acct_idsource: Some(1),
        alloc_settl_currency: Some("EUR"),
        individual_alloc_id: Some("ALLOC-1"),
        no_nested_party_ids: &nested,
        alloc_qty: Some(Decimal::new(50, 0)),
    }];
    let order = NewOrderSingleFields {
        cl_ord_id: Some("ORDER-1"),
        side: Some(Side::Buy),
        transact_time: Some("20260712-10:00:01"),
        ord_type: Some(OrdType::Market),
        no_allocs: &allocs,
        ..NewOrderSingleFields::default()
    };
    let bytes = encode("D", |encoder| order.write(encoder));
    let mut decoder = Decoder::new(&bytes);
    let msg = ok(
        decoder.decode(),
        "the written frame decodes with its checksum",
    );
    assert_eq!(
        Validator::new(fix44_dictionary()).validate(&msg),
        Ok(()),
        "the written NewOrderSingle conforms to the FIX 4.4 dictionary"
    );

    let tags: Vec<u32> = msg.fields().map(|field| field.tag).collect();
    let start = some(tags.iter().position(|tag| *tag == 78), "NoAllocs");
    assert_eq!(
        tags.get(start..start + 9),
        Some(&[78, 79, 661, 736, 467, 539, 524, 538, 80][..])
    );

    let view = some(
        fix44::views::NewOrderSingleView::from_message(&msg),
        "a NewOrderSingle view",
    );
    let alloc = some(
        some(ok(view.no_allocs(), "NoAllocs"), "the allocations").next(),
        "one allocation",
    );
    assert_eq!(ok(alloc.alloc_qty(), "AllocQty"), Some(Decimal::new(50, 0)));
    let nested_party = some(
        some(
            ok(alloc.no_nested_party_ids(), "NoNestedPartyIDs"),
            "nested",
        )
        .next(),
        "one nested party",
    );
    assert_eq!(
        ok(nested_party.nested_party_id(), "NestedPartyID"),
        "NESTED-1"
    );
}

#[test]
fn test_generated_view_reads_an_empty_top_level_group_like_the_layout() {
    // NoPartyIDs(453) entries accept Text(58), and so does the
    // NewOrderSingle message level. With a count of 0 the 58 that follows is
    // the message's: MessageLayout knows it from the message level's tags,
    // and the generated static set carries the same tags.
    let dict = views_common::views_sample_dictionary();
    let layout = ok(MessageLayout::new(&dict, "D"), "the sample layout");
    assert_eq!(
        sample::layouts::NEW_ORDER_SINGLE.level_tags(),
        layout.groups().level_tags()
    );
    for body in [
        &["11=ORDER-1", "54=1", "453=0", "58=top"][..],
        &[
            "11=ORDER-1",
            "54=1",
            "453=1",
            "448=A",
            "452=1",
            "58=in",
            "58=top",
        ][..],
        &[
            "11=ORDER-1",
            "54=1",
            "453=1",
            "448=A",
            "452=1",
            "802=0",
            "58=in",
        ][..],
    ] {
        let bytes = frame("D", body);
        let msg = decode(&bytes);
        let view = some(
            sample::views::NewOrderSingleView::from_message(&msg),
            "a sample view",
        );
        let from_view = view
            .no_party_ids()
            .map(|parties| parties.map(|parties| parties.count()));
        let from_layout = layout
            .read(&msg, 453)
            .map(|parties| parties.map(Iterator::count));
        assert_eq!(from_view, from_layout, "{body:?}");
        assert_eq!(
            ok(view.text(), "message-level Text"),
            layout
                .groups()
                .field(&msg, 58)
                .map(|field| std::str::from_utf8(field.value).unwrap_or_default()),
            "{body:?}"
        );
    }
    let bytes = frame("D", &["11=ORDER-1", "54=1", "453=0", "58=top"]);
    let msg = decode(&bytes);
    let view = some(
        sample::views::NewOrderSingleView::from_message(&msg),
        "a sample view",
    );
    assert_eq!(
        ok(view.no_party_ids(), "an empty NoPartyIDs").map(Iterator::count),
        Some(0)
    );
    assert_eq!(ok(view.text(), "message-level Text"), Some("top"));
}

#[test]
fn test_writer_refuses_values_that_do_not_match_their_fix_type() {
    use sample::enums::{Flags, Side};
    use sample::writers::{NewOrderSingleFields, TypeSamplerFields, TypeSamplerNoDocsFields};

    let calls = Cell::new(0usize);
    let docs = [TypeSamplerNoDocsFields {
        encoded_text: Some(&b"x"[..]),
        doc_name: None,
    }];
    let valid = TypeSamplerFields {
        no_docs: &docs,
        ..TypeSamplerFields::default()
    };
    let refused = |fields: TypeSamplerFields<'_>, tag: u32, what: &str| {
        let mut sink = |_tag: u32, _value: &[u8]| calls.set(calls.get() + 1);
        assert!(
            matches!(
                fields.write(&mut sink),
                Err(EncodeError::InvalidFieldValue { tag: found, .. }) if found == tag
            ),
            "{what}"
        );
    };
    refused(
        TypeSamplerFields {
            transact_time: Some("2026-07-12 10:00"),
            ..valid
        },
        60,
        "a malformed UTCTimestamp",
    );
    refused(
        TypeSamplerFields {
            sample_time: Some("10:00"),
            ..valid
        },
        5010,
        "a malformed UTCTimeOnly",
    );
    refused(
        TypeSamplerFields {
            maturity_month_year: Some("2026"),
            ..valid
        },
        200,
        "a malformed MonthYear",
    );
    refused(
        TypeSamplerFields {
            currency: Some("EU"),
            ..valid
        },
        15,
        "a two-letter Currency",
    );
    refused(
        TypeSamplerFields {
            country: Some("USA"),
            ..valid
        },
        421,
        "a three-letter Country",
    );
    for day in [0, 32] {
        refused(
            TypeSamplerFields {
                maturity_day: Some(day),
                ..valid
            },
            205,
            "a DayOfMonth outside 1 to 31",
        );
    }
    refused(
        TypeSamplerFields {
            labels: Some("a  b"),
            ..valid
        },
        5013,
        "an empty MultipleStringValue token",
    );
    refused(
        TypeSamplerFields {
            flags: &[Flags::Alpha, Flags::Other(b"AB")],
            ..valid
        },
        5014,
        "a MultipleCharValue token longer than one character",
    );
    let order = NewOrderSingleFields {
        cl_ord_id: Some("ORDER-1"),
        side: Some(Side::Other(b"AB")),
        transact_time: Some("20260712-10:00:01"),
        symbol: Some("EURUSD"),
        ..NewOrderSingleFields::default()
    };
    let mut sink = |_tag: u32, _value: &[u8]| calls.set(calls.get() + 1);
    assert!(
        matches!(
            order.write(&mut sink),
            Err(EncodeError::InvalidFieldValue { tag: 54, .. })
        ),
        "an undeclared value too long for a char field"
    );
    assert_eq!(calls.get(), 0, "nothing is written when a check fails");

    // The same fields with well-formed values write, and validate.
    let sampler = TypeSamplerFields {
        transact_time: Some("20260712-10:00:00.123"),
        sample_time: Some("10:00:00"),
        sample_date: Some("20260712"),
        trade_date: Some("20260712"),
        maturity_month_year: Some("202607w2"),
        maturity_day: Some(31),
        country: Some("US"),
        currency: Some("EUR"),
        labels: Some("a b"),
        flags: &[Flags::Alpha, Flags::Bravo],
        no_docs: &docs,
        ..TypeSamplerFields::default()
    };
    let bytes = encode("U1", |encoder| sampler.write(encoder));
    let mut decoder = Decoder::new(&bytes);
    let msg = ok(decoder.decode(), "the written frame decodes");
    let dict = views_common::views_sample_dictionary();
    assert_eq!(Validator::new(&dict).validate(&msg), Ok(()));
}

#[test]
fn test_writer_refuses_an_enumerated_character_that_is_not_printable_ascii() {
    use sample::enums::{Flags, Side};
    use sample::writers::{NewOrderSingleFields, TypeSamplerFields, TypeSamplerNoDocsFields};

    // One `char` of the FIX type, but not printable ASCII: the rule of a
    // plain `char` field applies to the enumeration of a `char` field and to
    // every token of a `MultipleCharValue` field.
    let calls = Cell::new(0usize);
    let mut sink = |_tag: u32, _value: &[u8]| calls.set(calls.get() + 1);
    for side in [
        Side::Other(b"\0"),
        Side::Other("é".as_bytes()),
        Side::Other(b"\x7f"),
    ] {
        let order = NewOrderSingleFields {
            cl_ord_id: Some("ORDER-1"),
            side: Some(side),
            transact_time: Some("20260712-10:00:01"),
            symbol: Some("EURUSD"),
            ..NewOrderSingleFields::default()
        };
        assert!(
            matches!(
                order.write(&mut sink),
                Err(EncodeError::InvalidFieldValue { tag: 54, .. })
            ),
            "{side:?}"
        );
    }
    let docs = [TypeSamplerNoDocsFields {
        encoded_text: Some(&b"x"[..]),
        doc_name: None,
    }];
    for token in [Flags::Other(b"\n"), Flags::Other("é".as_bytes())] {
        let sampler = TypeSamplerFields {
            flags: &[Flags::Alpha, token],
            no_docs: &docs,
            ..TypeSamplerFields::default()
        };
        assert!(
            matches!(
                sampler.write(&mut sink),
                Err(EncodeError::InvalidFieldValue { tag: 5014, .. })
            ),
            "{token:?}"
        );
    }
    assert_eq!(calls.get(), 0, "nothing is written when a check fails");

    // A printable undeclared character, and a space-free printable token,
    // still write.
    let order = NewOrderSingleFields {
        cl_ord_id: Some("ORDER-1"),
        side: Some(Side::Other(b"Z")),
        transact_time: Some("20260712-10:00:01"),
        symbol: Some("EURUSD"),
        ..NewOrderSingleFields::default()
    };
    assert!(order.write(&mut sink).is_ok());
    let sampler = TypeSamplerFields {
        flags: &[Flags::Alpha, Flags::Other(b"~")],
        no_docs: &docs,
        ..TypeSamplerFields::default()
    };
    assert!(sampler.write(&mut sink).is_ok());
}
