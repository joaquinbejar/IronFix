/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! Version-parameterised FIX message construction shared by the runnable
//! examples.
//!
//! The nine `fixNN_client` / `fixNN_server` example pairs differ only in which
//! FIX version they speak. That difference is expressed here once, as data on
//! [`FixVersion`], instead of nine copies of the same builders — the copies had
//! already drifted apart into protocol bugs (a hard-coded `MsgSeqNum`, a FIX 4.1
//! `ExecutionReport` under a `FIX.4.0` header).
//!
//! This module lives in `src/` rather than in `examples/common/` on purpose:
//! `cargo test` does not run tests declared inside an example target, so
//! anything that must be *verified* — sequence-number allocation and the
//! per-version field sets — has to be a library module. The socket plumbing
//! that consumes it stays in `examples/common/mod.rs`.
//!
//! # What is version-specific
//!
//! | | 4.0 | 4.1 – 4.2 | 4.3 – 4.4 | 5.0 family |
//! |---|---|---|---|---|
//! | `BeginString` (8) | `FIX.4.0` | own name | own name | `FIXT.1.1` |
//! | `DefaultApplVerID` (1137) on Logon | — | — | — | `7` / `8` / `9` |
//! | `ApplVerID` (1128) on app messages | — | — | — | `7` / `8` / `9` |
//! | `ExecTransType` (20) in an ExecutionReport | required | required | — | — |
//! | `ExecType` (150) | — | required | required | required |
//! | `LeavesQty` (151) | — | required | required | required |
//! | `OrderQty` (38) / `LastShares` (32) / `LastPx` (31) | required | required | — | — |
//!
//! The columns follow `doc/fix_operations.md`, "Version-Specific
//! Considerations" and "Execution Report (MsgType = 8)". FIX 4.1 and 4.2 are a
//! transition: they carry `ExecTransType` (20) and the order-plus-fill fields
//! (38 / 32 / 31) inherited from 4.0 **and** the `ExecType` (150) / `LeavesQty`
//! (151) pair introduced in 4.1 — emitting only 151 would drop three required
//! fields. The three 5.0 variants differ **only** in the `ApplVerID` code they
//! negotiate:
//! IronFix has no application-layer coverage that is specific to SP1 or SP2, so
//! those pairs demonstrate FIXT.1.1 transport and nothing more. Do not read them
//! as evidence of SP-specific message support.
//!
//! # What is not modelled
//!
//! These are demonstration builders, not a session engine. They allocate
//! outbound sequence numbers and stamp the standard header; they do not persist
//! messages, answer a `ResendRequest`, or drive a state machine. For that, use
//! [`ironfix_engine::Initiator`] — `examples/fix44_engine_client.rs` shows it.

use ironfix_core::error::EncodeError;
use ironfix_core::{FixVersion, MsgType, SeqNum, Side, Timestamp};
use ironfix_session::{SequenceExhausted, SequenceManager};
use ironfix_tagvalue::Encoder;
use rust_decimal::Decimal;
use thiserror::Error;

/// A failure while building a demonstration message.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DemoError {
    /// The encoder refused a field value or the finished frame.
    #[error("encoding the {msg_type} message failed")]
    Encode {
        /// Wire code of the message being built, e.g. `A` for a Logon.
        msg_type: &'static str,
        /// The rejection the encoder recorded.
        #[source]
        source: EncodeError,
    },

    /// The outbound sequence counter is exhausted.
    ///
    /// A real session answers this with a sequence reset; a demo has nothing
    /// sensible to do but stop.
    #[error(transparent)]
    Sequence(#[from] SequenceExhausted),

    /// A FIXT.1.1 session was configured with a version that names no
    /// application version.
    ///
    /// `DefaultApplVerID` (1137) is required on a FIXT Logon, and
    /// [`FixVersion::Fixt11`] alone does not say which application version the
    /// session carries. Guessing one would put a fabricated field on the wire.
    #[error("{version} names no application version, so DefaultApplVerID (1137) cannot be stamped")]
    NoApplVerId {
        /// The version that could not supply an `ApplVerID`.
        version: FixVersion,
    },
}

/// A `NewOrderSingle` to send.
///
/// `price` is a [`Decimal`]: a FIX price is an exact decimal quantity, and
/// binary floating point cannot represent one. See `CLAUDE.md`, "Governance
/// precedence", override 3.
#[derive(Debug, Clone)]
pub struct DemoOrder<'a> {
    /// `ClOrdID` (11).
    pub cl_ord_id: &'a str,
    /// `Symbol` (55).
    pub symbol: &'a str,
    /// `Side` (54).
    pub side: Side,
    /// `OrderQty` (38).
    pub quantity: u64,
    /// `Price` (44).
    pub price: Decimal,
}

/// A `NewOrderSingle` as received, ready to be acknowledged.
///
/// Holds only what the client sent. The identifiers the acceptor assigns —
/// `OrderID` (37) and `ExecID` (17) — are arguments to
/// [`DemoSession::execution_report`] instead of fields here, so they do not
/// have to be borrowed for as long as the decoded frame.
#[derive(Debug, Clone)]
pub struct IncomingOrder<'a> {
    /// `ClOrdID` (11).
    pub cl_ord_id: &'a str,
    /// `Symbol` (55).
    pub symbol: &'a str,
    /// `Side` (54).
    pub side: Side,
    /// `OrderQty` (38).
    pub order_qty: u64,
}

impl<'a> IncomingOrder<'a> {
    /// Reads an order out of a decoded `NewOrderSingle`.
    ///
    /// # Arguments
    /// * `order` - The decoded incoming message
    ///
    /// # Returns
    /// `None` if a required field is missing or unusable — an absent
    /// `ClOrdID`, a `Side` outside the tag-54 enumeration, or a non-numeric
    /// `OrderQty`. The caller answers that with a session-level `Reject`
    /// ([`DemoSession::reject`]) rather than substituting a default, which
    /// would acknowledge an order the client never placed.
    #[must_use]
    pub fn from_new_order(order: &ironfix_core::RawMessage<'a>) -> Option<Self> {
        Self::from_parts(
            order.get_field_str(11)?,
            order.get_field_str(55)?,
            order.get_field_str(54)?,
            order.get_field_str(38)?,
        )
    }

    /// Builds an order from field values already extracted from a
    /// `NewOrderSingle`.
    ///
    /// For callers that decoded the order elsewhere — `fix44_server_channel`
    /// forwards a copy of the fields to a processor task rather than a borrowed
    /// frame.
    ///
    /// # Arguments
    /// * `cl_ord_id` - `ClOrdID` (11) from the order
    /// * `symbol` - `Symbol` (55) from the order
    /// * `side` - `Side` (54) from the order, as text
    /// * `order_qty` - `OrderQty` (38) from the order, as text
    ///
    /// # Returns
    /// `None` if `side` is not a single character in the tag-54 enumeration, or
    /// `order_qty` is not a non-negative integer.
    #[must_use]
    pub fn from_parts(
        cl_ord_id: &'a str,
        symbol: &'a str,
        side: &str,
        order_qty: &str,
    ) -> Option<Self> {
        let side = side
            .chars()
            .next()
            .filter(|_| side.chars().count() == 1)
            .and_then(Side::from_char)?;
        let order_qty = order_qty.parse::<u64>().ok()?;

        Some(Self {
            cl_ord_id,
            symbol,
            side,
            order_qty,
        })
    }
}

/// Builds the messages of one side of a demonstration FIX session.
///
/// Owns the outbound sequence counter, so every frame it produces carries the
/// next `MsgSeqNum` (34) rather than a constant. The inbound counter is exposed
/// through [`DemoSession::sequences`] for the caller to validate against.
///
/// The [`Encoder`] is held across messages and reused, so building a frame
/// after the first allocates nothing for the frame itself.
#[derive(Debug)]
pub struct DemoSession {
    /// Version this side speaks.
    version: FixVersion,
    /// `SenderCompID` (49).
    sender_comp_id: String,
    /// `TargetCompID` (56).
    target_comp_id: String,
    /// `HeartBtInt` (108), in seconds.
    heartbeat_interval: u64,
    /// Both sequence counters.
    sequences: SequenceManager,
    /// Reused frame buffer.
    encoder: Encoder,
}

impl DemoSession {
    /// Creates a session for `version` between two `CompID`s.
    ///
    /// # Arguments
    /// * `version` - FIX version, which fixes `BeginString` and any `ApplVerID`
    /// * `sender_comp_id` - `SenderCompID` (49) of this side
    /// * `target_comp_id` - `TargetCompID` (56) of the counterparty
    /// * `heartbeat_interval` - `HeartBtInt` (108), in seconds
    #[must_use]
    pub fn new(
        version: FixVersion,
        sender_comp_id: &str,
        target_comp_id: &str,
        heartbeat_interval: u64,
    ) -> Self {
        Self {
            version,
            sender_comp_id: sender_comp_id.to_string(),
            target_comp_id: target_comp_id.to_string(),
            heartbeat_interval,
            sequences: SequenceManager::new(),
            encoder: Encoder::new(version.begin_string()),
        }
    }

    /// Returns the FIX version this session speaks.
    #[must_use]
    pub const fn version(&self) -> FixVersion {
        self.version
    }

    /// Returns the sequence counters, for validating an inbound `MsgSeqNum`.
    #[must_use]
    pub const fn sequences(&self) -> &SequenceManager {
        &self.sequences
    }

    /// Returns the next outbound sequence number without allocating it.
    #[must_use]
    pub fn next_sender_seq(&self) -> SeqNum {
        self.sequences.next_sender_seq()
    }

    /// Builds a `Logon` (35=A).
    ///
    /// A FIXT.1.1 session additionally carries `DefaultApplVerID` (1137).
    ///
    /// # Errors
    /// [`DemoError::Sequence`] if the outbound counter is exhausted,
    /// [`DemoError::NoApplVerId`] for a FIXT session whose version names no
    /// application version, or [`DemoError::Encode`] if the encoder refused a
    /// field.
    pub fn logon(&mut self) -> Result<&[u8], DemoError> {
        self.start(MsgType::Logon.as_str())?;
        self.encoder.put_str(98, "0");
        self.encoder.put_uint(108, self.heartbeat_interval);
        if self.version.uses_fixt() {
            let appl_ver_id = self.version.appl_ver_id().ok_or(DemoError::NoApplVerId {
                version: self.version,
            })?;
            self.encoder.put_str(1137, appl_ver_id);
        }
        self.finish("Logon")
    }

    /// Builds a `Heartbeat` (35=0), echoing `TestReqID` (112) when it answers a
    /// `TestRequest`.
    ///
    /// # Arguments
    /// * `test_req_id` - `TestReqID` of the request being answered, if any
    ///
    /// # Errors
    /// As [`DemoSession::logon`], minus [`DemoError::NoApplVerId`].
    pub fn heartbeat(&mut self, test_req_id: Option<&str>) -> Result<&[u8], DemoError> {
        self.start(MsgType::Heartbeat.as_str())?;
        if let Some(id) = test_req_id {
            self.encoder.put_str(112, id);
        }
        self.finish("Heartbeat")
    }

    /// Builds a `TestRequest` (35=1).
    ///
    /// # Arguments
    /// * `test_req_id` - `TestReqID` (112) the peer must echo
    ///
    /// # Errors
    /// As [`DemoSession::heartbeat`].
    pub fn test_request(&mut self, test_req_id: &str) -> Result<&[u8], DemoError> {
        self.start(MsgType::TestRequest.as_str())?;
        self.encoder.put_str(112, test_req_id);
        self.finish("TestRequest")
    }

    /// Builds a `Logout` (35=5).
    ///
    /// # Arguments
    /// * `text` - Optional `Text` (58) explaining the logout
    ///
    /// # Errors
    /// As [`DemoSession::heartbeat`].
    pub fn logout(&mut self, text: Option<&str>) -> Result<&[u8], DemoError> {
        self.start(MsgType::Logout.as_str())?;
        if let Some(text) = text {
            self.encoder.put_str(58, text);
        }
        self.finish("Logout")
    }

    /// Builds a session-level `Reject` (35=3).
    ///
    /// # Arguments
    /// * `ref_seq_num` - `RefSeqNum` (45) of the rejected message
    /// * `ref_tag_id` - `RefTagID` (371) when a single field is at fault
    /// * `text` - `Text` (58) describing the rejection
    ///
    /// # Errors
    /// As [`DemoSession::heartbeat`].
    pub fn reject(
        &mut self,
        ref_seq_num: u64,
        ref_tag_id: Option<u32>,
        text: &str,
    ) -> Result<&[u8], DemoError> {
        self.start(MsgType::Reject.as_str())?;
        self.encoder.put_uint(45, ref_seq_num);
        if let Some(tag) = ref_tag_id {
            self.encoder.put_uint(371, u64::from(tag));
        }
        self.encoder.put_str(58, text);
        self.finish("Reject")
    }

    /// Builds a `NewOrderSingle` (35=D) for a limit order.
    ///
    /// # Arguments
    /// * `order` - The order to send
    ///
    /// # Errors
    /// As [`DemoSession::heartbeat`].
    pub fn new_order_single(&mut self, order: &DemoOrder<'_>) -> Result<&[u8], DemoError> {
        self.start_app(MsgType::NewOrderSingle.as_str())?;
        self.encoder.put_str(11, order.cl_ord_id);
        self.encoder.put_str(21, "1");
        self.encoder.put_str(55, order.symbol);
        self.encoder.put_char(54, order.side.as_char());
        // TransactTime (60) enters NewOrderSingle in FIX 4.2; 4.0 and 4.1 have
        // no such field, so emitting it there would be out of schema.
        if !matches!(self.version, FixVersion::Fix40 | FixVersion::Fix41) {
            self.encoder
                .put_str(60, Timestamp::now().format_millis().as_str());
        }
        self.encoder.put_uint(38, order.quantity);
        self.encoder.put_str(40, "2");
        let price = order.price.to_string();
        self.encoder.put_str(44, &price);
        self.finish("NewOrderSingle")
    }

    /// Builds an `ExecutionReport` (35=8) acknowledging an order as `New`.
    ///
    /// The field set follows the FIX version this session speaks; see the
    /// module documentation for the table.
    ///
    /// # Arguments
    /// * `order` - The order being acknowledged
    /// * `order_id` - `OrderID` (37) the acceptor assigns
    /// * `exec_id` - `ExecID` (17) the acceptor assigns
    ///
    /// # Errors
    /// As [`DemoSession::heartbeat`].
    pub fn execution_report(
        &mut self,
        order: &IncomingOrder<'_>,
        order_id: &str,
        exec_id: &str,
    ) -> Result<&[u8], DemoError> {
        self.start_app(MsgType::ExecutionReport.as_str())?;
        self.encoder.put_str(37, order_id);
        self.encoder.put_str(11, order.cl_ord_id);
        self.encoder.put_str(17, exec_id);

        // ExecTransType (20) is required through 4.2 and gone from 4.3 on,
        // where ExecType (150) replaces it. FIX 4.0 has no ExecType at all.
        if matches!(
            self.version,
            FixVersion::Fix40 | FixVersion::Fix41 | FixVersion::Fix42
        ) {
            self.encoder.put_str(20, "0");
        }
        if self.version != FixVersion::Fix40 {
            self.encoder.put_str(150, "0");
        }

        self.encoder.put_str(39, "0");
        self.encoder.put_str(55, order.symbol);
        self.encoder.put_char(54, order.side.as_char());

        // OrderQty (38) / LastShares (32) / LastPx (31): the order-plus-fill
        // view, with an empty last fill for a New. Required through 4.2 — in
        // 4.0-4.1 as the only quantity fields, in 4.2 alongside LeavesQty —
        // and dropped as required from 4.3 on. This is the field set the
        // pre-fix else-branch used to omit for 4.1 and 4.2.
        if matches!(
            self.version,
            FixVersion::Fix40 | FixVersion::Fix41 | FixVersion::Fix42
        ) {
            self.encoder.put_uint(38, order.order_qty);
            self.encoder.put_uint(32, 0);
            self.put_price(31, Decimal::ZERO);
        }
        // LeavesQty (151): the unfilled quantity, present from 4.1 on. FIX 4.0
        // has no LeavesQty.
        if self.version != FixVersion::Fix40 {
            self.encoder.put_uint(151, order.order_qty);
        }

        self.encoder.put_uint(14, 0);
        self.put_price(6, Decimal::ZERO);
        self.finish("ExecutionReport")
    }

    /// Returns the `ApplVerID` (1128) an application message carries, or `None`
    /// for a pre-5.0 session.
    fn appl_ver_id_for_app_message(&self) -> Option<&'static str> {
        if self.version.uses_fixt() {
            self.version.appl_ver_id()
        } else {
            None
        }
    }

    /// Writes a monetary value as its exact decimal text.
    fn put_price(&mut self, tag: u32, value: Decimal) {
        let text = value.to_string();
        self.encoder.put_str(tag, &text);
    }

    /// Starts a session-level message, whose header carries no `ApplVerID`.
    fn start(&mut self, msg_type: &str) -> Result<(), DemoError> {
        self.start_with_appl_ver_id(msg_type, None)
    }

    /// Starts an application message, stamping `ApplVerID` (1128) into the
    /// FIXT.1.1 header of a 5.0-family session.
    fn start_app(&mut self, msg_type: &str) -> Result<(), DemoError> {
        let appl_ver_id = self.appl_ver_id_for_app_message();
        self.start_with_appl_ver_id(msg_type, appl_ver_id)
    }

    /// Starts a message: clears the buffer and writes the standard header
    /// fields the encoder does not stamp itself.
    ///
    /// `BeginString` (8), `BodyLength` (9) and `CheckSum` (10) belong to
    /// [`Encoder::finish`]; `MsgType` (35) must be the first body field. When a
    /// FIXT.1.1 session stamps `ApplVerID` (1128) it goes immediately after
    /// `MsgType`, ahead of `SenderCompID` (49), where the standard header
    /// places it — not down in the body.
    ///
    /// The sequence number is *peeked*, not allocated: [`DemoSession::finish`]
    /// commits it only once the frame encodes, so a failed encode leaves no gap
    /// in the outbound sequence.
    fn start_with_appl_ver_id(
        &mut self,
        msg_type: &str,
        appl_ver_id: Option<&'static str>,
    ) -> Result<(), DemoError> {
        let seq = self.sequences.next_sender_seq();
        self.encoder.clear();
        self.encoder.put_str(35, msg_type);
        if let Some(appl_ver_id) = appl_ver_id {
            self.encoder.put_str(1128, appl_ver_id);
        }
        self.encoder.put_str(49, &self.sender_comp_id);
        self.encoder.put_str(56, &self.target_comp_id);
        self.encoder.put_uint(34, seq.value());
        self.encoder
            .put_str(52, Timestamp::now().format_millis().as_str());
        Ok(())
    }

    /// Stamps the frame and commits the sequence number, naming the message in
    /// any rejection.
    ///
    /// The counter is advanced only here, after the frame encodes:
    /// [`DemoSession::start`] peeked the number for `MsgSeqNum` (34) but did not
    /// consume it, so a failed encode does not burn a sequence number and leave
    /// the peer expecting a message that was never sent. An exhausted counter
    /// surfaces as [`DemoError::Sequence`] and the frame is discarded.
    fn finish(&mut self, msg_type: &'static str) -> Result<&[u8], DemoError> {
        let frame = self
            .encoder
            .finish()
            .map_err(|source| DemoError::Encode { msg_type, source })?;
        self.sequences.try_allocate_sender_seq()?;
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironfix_tagvalue::Decoder;

    /// Builds a session for `version` with fixed CompIDs.
    fn session(version: FixVersion) -> DemoSession {
        DemoSession::new(version, "SENDER", "TARGET", 30)
    }

    /// Decodes a frame and returns the value of `tag`, if present.
    fn field(frame: &[u8], tag: u32) -> Option<String> {
        let mut decoder = Decoder::new(frame);
        let raw = decoder.decode().ok()?;
        raw.get_field_str(tag).map(str::to_string)
    }

    /// Builds a Logon, an ExecutionReport and a Logout, returning them owned.
    fn three_frames(version: FixVersion) -> Vec<Vec<u8>> {
        let mut demo = session(version);
        let order = IncomingOrder {
            cl_ord_id: "C1",
            symbol: "IBM",
            side: Side::Buy,
            order_qty: 100,
        };

        let logon = demo.logon().expect("logon encodes").to_vec();
        let exec = demo
            .execution_report(&order, "ORD1", "EX1")
            .expect("execution report encodes")
            .to_vec();
        let logout = demo.logout(None).expect("logout encodes").to_vec();
        vec![logon, exec, logout]
    }

    #[test]
    fn msg_seq_num_increments_across_every_message() {
        for version in FixVersion::ALL {
            if version == FixVersion::Fixt11 {
                continue;
            }
            let frames = three_frames(version);
            let seqs: Vec<Option<String>> = frames.iter().map(|f| field(f, 34)).collect();
            assert_eq!(
                seqs,
                vec![
                    Some("1".to_string()),
                    Some("2".to_string()),
                    Some("3".to_string())
                ],
                "{version} did not stamp an incrementing MsgSeqNum"
            );
        }
    }

    #[test]
    fn every_version_stamps_its_own_begin_string() {
        for version in FixVersion::ALL {
            if version == FixVersion::Fixt11 {
                continue;
            }
            let mut demo = session(version);
            let frame = demo.logon().expect("logon encodes").to_vec();
            let expected = format!("8={}\x01", version.begin_string());
            assert!(
                frame.starts_with(expected.as_bytes()),
                "{version} framed as {:?}",
                String::from_utf8_lossy(&frame[..12.min(frame.len())])
            );
        }
    }

    #[test]
    fn fix40_execution_report_omits_fields_introduced_after_40() {
        let mut demo = session(FixVersion::Fix40);
        let order = IncomingOrder {
            cl_ord_id: "C1",
            symbol: "IBM",
            side: Side::Buy,
            order_qty: 100,
        };
        let frame = demo
            .execution_report(&order, "ORD1", "EX1")
            .expect("encodes")
            .to_vec();

        assert_eq!(field(&frame, 150), None, "ExecType is a FIX 4.1 field");
        assert_eq!(field(&frame, 151), None, "LeavesQty is a FIX 4.1 field");
        assert_eq!(field(&frame, 20).as_deref(), Some("0"), "ExecTransType");
        assert_eq!(field(&frame, 38).as_deref(), Some("100"), "OrderQty");
        assert_eq!(field(&frame, 32).as_deref(), Some("0"), "LastShares");
        assert_eq!(field(&frame, 31).as_deref(), Some("0"), "LastPx");
    }

    #[test]
    fn fix44_execution_report_uses_exec_type_not_exec_trans_type() {
        let mut demo = session(FixVersion::Fix44);
        let order = IncomingOrder {
            cl_ord_id: "C1",
            symbol: "IBM",
            side: Side::Sell,
            order_qty: 250,
        };
        let frame = demo
            .execution_report(&order, "ORD1", "EX1")
            .expect("encodes")
            .to_vec();

        assert_eq!(field(&frame, 150).as_deref(), Some("0"), "ExecType");
        assert_eq!(field(&frame, 151).as_deref(), Some("250"), "LeavesQty");
        assert_eq!(field(&frame, 20), None, "ExecTransType is gone from 4.3 on");
        assert_eq!(field(&frame, 32), None, "LastShares is not required in 4.4");
        assert_eq!(field(&frame, 54).as_deref(), Some("2"), "Side is echoed");
    }

    #[test]
    fn fix41_and_fix42_execution_reports_carry_the_full_required_set() {
        // 4.1 and 4.2 require ExecTransType (20) AND ExecType (150) /
        // LeavesQty (151) AND the order-plus-fill fields OrderQty (38) /
        // LastShares (32) / LastPx (31). Emitting only 151 — the bug this
        // guards against — silently drops three required fields.
        for version in [FixVersion::Fix41, FixVersion::Fix42] {
            let mut demo = session(version);
            let order = IncomingOrder {
                cl_ord_id: "C1",
                symbol: "IBM",
                side: Side::Buy,
                order_qty: 10,
            };
            let frame = demo
                .execution_report(&order, "ORD1", "EX1")
                .expect("encodes")
                .to_vec();

            assert_eq!(
                field(&frame, 20).as_deref(),
                Some("0"),
                "{version} ExecTransType"
            );
            assert_eq!(
                field(&frame, 150).as_deref(),
                Some("0"),
                "{version} ExecType"
            );
            assert_eq!(
                field(&frame, 151).as_deref(),
                Some("10"),
                "{version} LeavesQty"
            );
            assert_eq!(
                field(&frame, 38).as_deref(),
                Some("10"),
                "{version} OrderQty"
            );
            assert_eq!(
                field(&frame, 32).as_deref(),
                Some("0"),
                "{version} LastShares"
            );
            assert_eq!(field(&frame, 31).as_deref(), Some("0"), "{version} LastPx");
        }
    }

    #[test]
    fn fixt_sessions_stamp_appl_ver_id_and_pre_50_sessions_do_not() {
        let cases = [
            (FixVersion::Fix50, Some("7")),
            (FixVersion::Fix50Sp1, Some("8")),
            (FixVersion::Fix50Sp2, Some("9")),
            (FixVersion::Fix44, None),
            (FixVersion::Fix40, None),
        ];

        for (version, expected) in cases {
            let mut demo = session(version);
            let logon = demo.logon().expect("logon encodes").to_vec();
            assert_eq!(
                field(&logon, 1137).as_deref(),
                expected,
                "{version} DefaultApplVerID"
            );

            let order = IncomingOrder {
                cl_ord_id: "C",
                symbol: "IBM",
                side: Side::Buy,
                order_qty: 1,
            };
            let exec = demo
                .execution_report(&order, "O", "E")
                .expect("encodes")
                .to_vec();
            assert_eq!(
                field(&exec, 1128).as_deref(),
                expected,
                "{version} ApplVerID"
            );
        }
    }

    #[test]
    fn fixt11_alone_cannot_build_a_logon() {
        let mut demo = session(FixVersion::Fixt11);
        match demo.logon() {
            Err(DemoError::NoApplVerId { version }) => {
                assert_eq!(version, FixVersion::Fixt11);
            }
            other => panic!("expected NoApplVerId, got {:?}", other.map(<[u8]>::to_vec)),
        }
    }

    #[test]
    fn price_is_written_as_exact_decimal_text() {
        let mut demo = session(FixVersion::Fix44);
        let order = DemoOrder {
            cl_ord_id: "C1",
            symbol: "IBM",
            side: Side::Buy,
            quantity: 100,
            // 0.1 + 0.2 is not 0.3 in binary floating point; it is here.
            price: Decimal::new(1, 1) + Decimal::new(2, 1),
        };
        let frame = demo.new_order_single(&order).expect("encodes").to_vec();
        assert_eq!(field(&frame, 44).as_deref(), Some("0.3"));
    }

    #[test]
    fn transact_time_is_gated_to_fix42_and_later() {
        // TransactTime (60) enters NewOrderSingle in FIX 4.2. 4.0 and 4.1 have
        // no such field; 4.2 and later require it.
        let order = DemoOrder {
            cl_ord_id: "C1",
            symbol: "IBM",
            side: Side::Buy,
            quantity: 100,
            price: Decimal::new(10, 1),
        };
        for version in [FixVersion::Fix40, FixVersion::Fix41] {
            let mut demo = session(version);
            let frame = demo.new_order_single(&order).expect("encodes").to_vec();
            assert_eq!(
                field(&frame, 60),
                None,
                "{version} must not emit TransactTime"
            );
        }
        for version in [FixVersion::Fix42, FixVersion::Fix44, FixVersion::Fix50] {
            let mut demo = session(version);
            let frame = demo.new_order_single(&order).expect("encodes").to_vec();
            assert!(
                field(&frame, 60).is_some(),
                "{version} must emit TransactTime"
            );
        }
    }

    #[test]
    fn appl_ver_id_sits_in_the_header_before_sender_comp_id() {
        // In a FIXT.1.1 header ApplVerID (1128) follows MsgType (35) and
        // precedes SenderCompID (49); it is not a body field after SendingTime.
        let mut demo = session(FixVersion::Fix50);
        let order = IncomingOrder {
            cl_ord_id: "C1",
            symbol: "IBM",
            side: Side::Buy,
            order_qty: 5,
        };
        let frame = demo.execution_report(&order, "O", "E").expect("encodes");
        let text = String::from_utf8_lossy(frame);
        let appl_ver_id = text.find("\x011128=").expect("1128 is present");
        let sender = text.find("\x0149=").expect("49 is present");
        assert!(
            appl_ver_id < sender,
            "ApplVerID (1128) must precede SenderCompID (49) in the header"
        );
    }

    #[test]
    fn every_frame_round_trips_through_the_decoder() {
        for version in FixVersion::ALL {
            if version == FixVersion::Fixt11 {
                continue;
            }
            for frame in three_frames(version) {
                let mut decoder = Decoder::new(&frame);
                let raw = decoder
                    .decode()
                    .unwrap_or_else(|e| panic!("{version} frame did not decode: {e}"));
                assert_eq!(
                    raw.begin_string().ok(),
                    Some(version.begin_string()),
                    "{version} BeginString"
                );
            }
        }
    }

    /// Encodes a well-formed `NewOrderSingle` whose body fields are `fields`.
    fn new_order_with(fields: &[(u32, &str)]) -> Vec<u8> {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "D");
        encoder.put_str(49, "CLIENT");
        encoder.put_str(56, "SERVER");
        encoder.put_uint(34, 2);
        for &(tag, value) in fields {
            encoder.put_str(tag, value);
        }
        encoder.finish().expect("encodes").to_vec()
    }

    #[test]
    fn incoming_order_accepts_a_well_formed_new_order() {
        let frame = new_order_with(&[(11, "C1"), (55, "IBM"), (54, "1"), (38, "100")]);
        let mut decoder = Decoder::new(&frame);
        let raw = decoder.decode().expect("decodes");

        let order = IncomingOrder::from_new_order(&raw).expect("accepted");
        assert_eq!(order.side, Side::Buy);
        assert_eq!(order.order_qty, 100);
        assert_eq!(order.symbol, "IBM");
    }

    #[test]
    fn incoming_order_refuses_a_new_order_with_an_unusable_side() {
        // `Z` is not in the tag 54 enumeration, and `12` is two characters.
        for side in ["Z", "12"] {
            let frame = new_order_with(&[(11, "C1"), (55, "IBM"), (54, side), (38, "100")]);
            let mut decoder = Decoder::new(&frame);
            let raw = decoder.decode().expect("decodes: the frame is well formed");
            assert!(
                IncomingOrder::from_new_order(&raw).is_none(),
                "Side {side:?} must not be acknowledged"
            );
        }
    }

    #[test]
    fn incoming_order_refuses_a_new_order_with_a_non_numeric_quantity() {
        let frame = new_order_with(&[(11, "C1"), (55, "IBM"), (54, "1"), (38, "lots")]);
        let mut decoder = Decoder::new(&frame);
        let raw = decoder.decode().expect("decodes");
        assert!(IncomingOrder::from_new_order(&raw).is_none());
    }

    #[test]
    fn incoming_order_refuses_a_new_order_missing_a_required_field() {
        for omitted in [11u32, 55, 54, 38] {
            let fields: Vec<(u32, &str)> = [(11, "C1"), (55, "IBM"), (54, "1"), (38, "100")]
                .into_iter()
                .filter(|&(tag, _)| tag != omitted)
                .collect();
            let frame = new_order_with(&fields);
            let mut decoder = Decoder::new(&frame);
            let raw = decoder.decode().expect("decodes");
            assert!(
                IncomingOrder::from_new_order(&raw).is_none(),
                "an order without tag {omitted} must not be acknowledged"
            );
        }
    }

    #[test]
    fn an_exhausted_sender_counter_is_an_error_not_a_wrap() {
        let mut demo = session(FixVersion::Fix44);
        demo.sequences.set_sender_seq(u64::MAX - 1);
        assert_eq!(
            field(demo.logon().expect("encodes"), 34).as_deref(),
            Some("18446744073709551614")
        );
        assert!(
            matches!(demo.heartbeat(None), Err(DemoError::Sequence(_))),
            "the counter must refuse to wrap back to a live sequence number"
        );
    }

    #[test]
    fn inbound_sequence_validation_reports_gaps() {
        use ironfix_session::sequence::SequenceResult;

        let demo = session(FixVersion::Fix44);
        assert_eq!(demo.sequences().validate_incoming(1), SequenceResult::Ok);
        assert!(matches!(
            demo.sequences().validate_incoming(5),
            SequenceResult::Gap {
                expected: 1,
                received: 5
            }
        ));
    }
}
