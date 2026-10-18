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

/// The embedded FIX 4.4 dictionary.
#[track_caller]
fn fix44_dictionary() -> &'static Dictionary {
    ok(Dictionary::fix44(), "the embedded FIX 4.4 dictionary loads")
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
    let exec_inst: Vec<ExecInst<'_>> = some(order.exec_inst(), "ExecInst").collect();
    assert_eq!(exec_inst, vec![ExecInst::NotHeld, ExecInst::AllOrNone]);
    assert_eq!(order.time_in_force(), Some(TimeInForce::Day));
    assert_eq!(ok(order.text(), "Text"), Some("hello"));
    // Absent optional fields read as None.
    assert_eq!(ok(order.stop_px(), "StopPx"), None);
    assert_eq!(ok(order.no_allocs(), "NoAllocs").map(Iterator::count), None);

    let mut parties = some(ok(order.no_party_ids(), "NoPartyIDs"), "the parties");
    assert_eq!(parties.len(), 2);
    let first = some(parties.next(), "the first party");
    assert_eq!(first.entry().index(), 0);
    assert_eq!(ok(first.party_id(), "PartyID"), "BROKER-A");
    assert_eq!(first.party_idsource(), Some(PartyIDSource::Proprietary));
    assert_eq!(first.party_role(), Some(PartyRole::ExecutingFirm));
    let mut sub_ids = some(ok(first.no_party_sub_ids(), "NoPartySubIDs"), "the sub-IDs");
    let sub_id = some(sub_ids.next(), "one sub-ID");
    assert_eq!(ok(sub_id.party_sub_id(), "PartySubID"), "SUB-1");
    assert_eq!(sub_id.party_sub_idtype(), Some(PartySubIDType::Person));
    assert!(sub_ids.next().is_none());
    let second = some(parties.next(), "the second party");
    assert_eq!(ok(second.party_id(), "PartyID"), "BROKER-B");
    assert_eq!(
        second.party_idsource(),
        Some(PartyIDSource::GeneralIdentifier)
    );
    assert_eq!(second.party_role(), Some(PartyRole::ClientId));
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
            "40=QQ",
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
    assert_eq!(ok(order.ord_type(), "OrdType"), OrdType::Other(b"QQ"));
    let tokens: Vec<ExecInst<'_>> = some(order.exec_inst(), "ExecInst").collect();
    assert_eq!(tokens, vec![ExecInst::NotHeld, ExecInst::Other(b"ZZ")]);

    // Every declared value round-trips through its wire bytes.
    for side in [Side::Buy, Side::Sell, Side::Cross] {
        assert_eq!(Side::from_bytes(side.as_bytes()), side);
    }
    // Values match on exact bytes.
    assert_eq!(Side::from_bytes(b"01"), Side::Other(b"01"));
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
    let read: Vec<ExecInst<'_>> = some(view.exec_inst(), "ExecInst").collect();
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
    assert_eq!(view.security_type(), Some(SecurityType::Quoted));
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
    assert_eq!(tags.first(), Some(&11), "dictionary order: ClOrdID first");
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
        fixt11::enums::EncryptMethod::NoneOther
    );
}
