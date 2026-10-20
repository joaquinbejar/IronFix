/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! Sans-IO core, stage 5: the decisions of the two Logon (A) handshakes.
//!
//! The initiator sends a Logon and validates the acknowledgement; the
//! acceptor validates a Logon and answers it. This module decides every step
//! of both that does not need the wire layer, the store or the application;
//! the driver parses the fields, runs `from_admin`, calls the store, writes
//! the frames and moves the typestate session.
//!
//! - **Who gets a reply (ADR-0017).** [`decide_logon_refusal`] says how a
//!   refused Logon is answered at each [`LogonStage`]: an acceptor never
//!   writes, and never touches its store, for a peer that is not
//!   authenticated yet when a store is attached, and nothing at all for a
//!   peer refused before admission while the session is live on another
//!   connection. [`default_appl_ver_id_required`] is the `DefaultApplVerID`
//!   (1137) rule of each role (issue #67).
//! - **`ResetSeqNumFlag` (141).** [`reset_flag_contradicts`] refuses a reset
//!   carried under a `MsgSeqNum` (34) other than 1. [`initiator_resets`] and
//!   [`acceptor_resets`] decide whether the exchange starts a new stream,
//!   [`owes_reset_durably`] whether that intent is recorded in the store
//!   first (issue #111, ADR-0029), and [`decide_ack_reset`] what an
//!   acknowledgement's 141 asks of an initiator that did not declare a reset.
//!   [`classify_logon_seq`] applies the reset rule both roles share before
//!   the Logon's number is validated, and [`decide_logon_gap`] whether a gap
//!   it opens is requested or held for the counterparty's 789 replay.
//! - **`HeartBtInt` (108).** [`negotiate_logon_interval`] bounds the
//!   counterparty's value per role, [`interval_change`] says whether the
//!   heartbeat clock is rebuilt, and [`AckHeartBtIntDefect`] is the
//!   `SessionRejectReason` (373) of an acknowledgement's unusable 108.
//! - **`NextExpectedMsgSeqNum` (789, ADR-0021).** [`declared_next_expected`]
//!   is the value this session declares, [`screen_next_expected`] drops a
//!   counterparty's value that describes a stream a one-sided reset discards,
//!   and [`plan_next_expected`] decides, against a [`NextExpectedBasis`],
//!   whether it asks for a replay ([`NextExpectedPlan`]) or for messages
//!   never sent ([`NextExpectedAhead`]).
//! - **Seeding.** [`decide_seed_source`] picks where the counters come from
//!   (a reset, an explicit seed, the store, or 1/1), [`seed_from_initial`],
//!   [`initial_below_store`] and [`seed_from_store`] compute them,
//!   [`initial_seed_applies`] and [`provisional_counters`] are the seed rules
//!   outside the seeding itself. [`inbound_loss_span`] is the span the start
//!   report of issue #105 (ADR-0030) names.
//! - **The mismatch report (issue #80, ADR-0015).** [`mismatch_report_applies`]
//!   gates it, [`LogonCounters`] holds the effective startup counters each
//!   role compares against, and [`compare_logon_sequences`] compares.
//! - **The logon timeout.** [`logon_deadline`] and [`logon_timed_out`] bound
//!   the wait for the Logon or its acknowledgement; [`logon_ack_deadline`]
//!   runs from the typestate's [`Session::sent_at`].
//!
//! Nothing here reads the Logon's bytes, so nothing here can log a
//! credential: `Password` (554), `NewPassword` (925) and `RawData` stay in
//! the driver, which hands them to `from_admin` only.

use crate::config::SessionConfig;
use crate::heartbeat::{HeartbeatIntervalError, MAX_HEARTBEAT_INTERVAL_SECS, negotiate_interval};
use crate::sequence::{SequenceCounter, SequenceManager, SequenceResult};
use crate::state::{LogonSent, Session};
use std::num::NonZeroU64;
use std::time::{Duration, Instant};

/// The side of the Logon exchange a session plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogonRole {
    /// Sends the Logon and validates the acknowledgement.
    Initiator,
    /// Validates the Logon and answers it with the acknowledgement.
    Acceptor,
}

/// How far a Logon got through the acceptor's checks when it was refused,
/// in the order ADR-0017 fixes.
///
/// The checks run in this order: `BeginString` (8), `EncryptMethod` (98),
/// `MsgSeqNum` (34) and the CompIDs before the admission slot is claimed
/// ([`LogonStage::BeforeAdmission`]); `SendingTime` (52) and `from_admin`
/// after it ([`LogonStage::Admitted`]); then, once `from_admin` has
/// accepted, `DefaultApplVerID` (1137), `ResetSeqNumFlag` (141), `HeartBtInt`
/// (108) and `NextExpectedMsgSeqNum` (789) ([`LogonStage::Authenticated`]).
/// The store is never touched before `from_admin` accepts. After that, an
/// accepted Logon resets or seeds the store only once the last of these
/// checks passes; a Logon refused at [`LogonStage::Authenticated`] is
/// answered with a Logout that is filed in the store
/// ([`LogonRefusal::Filed`]), numbered from counters that never reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogonStage {
    /// Refused before this connection claimed the session's admission slot.
    BeforeAdmission,
    /// The slot is claimed, but `from_admin` has not accepted the Logon: the
    /// peer is not authenticated (matching CompIDs prove nothing).
    Admitted,
    /// `from_admin` accepted the Logon: the peer is authenticated.
    Authenticated,
}

/// How a refused Logon is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogonRefusal {
    /// Nothing is written: the session is live on another connection, which
    /// owns the sequence stream, so any number the refusal took would reuse
    /// one of its numbers.
    SilentSessionLive,
    /// Nothing is written and the store is not touched: a store is attached
    /// and the peer is not authenticated. Filing a frame would let a peer
    /// that knows the CompIDs but not the credentials write to the outbound
    /// journal, and not filing it would reuse a number the stream holds.
    SilentStoreAttached,
    /// The refusal frames are written, numbered from the provisional
    /// counters ([`provisional_counters`]) and filed nowhere: an acceptor
    /// without a store refusing a peer that is not authenticated.
    Provisional,
    /// The refusal frames are written like every frame of the session:
    /// numbered from counters that never reset, and filed first when a store
    /// is attached.
    Filed,
}

/// Decides how a Logon refused at `stage` is answered (ADR-0017).
///
/// An initiator always files its refusal: it numbered and filed its own
/// Logon already, so its acknowledgement's refusal continues the same
/// stream. An acceptor answers an authenticated peer like any session frame;
/// a peer that is not authenticated gets nothing while the session is live
/// elsewhere (`stage` [`LogonStage::BeforeAdmission`] only: past it, the
/// slot is this connection's) or a store is attached, and a provisional
/// refusal otherwise.
#[must_use]
pub const fn decide_logon_refusal(
    role: LogonRole,
    stage: LogonStage,
    store_attached: bool,
    session_live: bool,
) -> LogonRefusal {
    match (role, stage) {
        (LogonRole::Initiator, _) | (LogonRole::Acceptor, LogonStage::Authenticated) => {
            LogonRefusal::Filed
        }
        (LogonRole::Acceptor, LogonStage::BeforeAdmission | LogonStage::Admitted) => {
            if matches!(stage, LogonStage::BeforeAdmission) && session_live {
                LogonRefusal::SilentSessionLive
            } else if store_attached {
                LogonRefusal::SilentStoreAttached
            } else {
                LogonRefusal::Provisional
            }
        }
    }
}

/// Whether the counterparty's Logon must carry `DefaultApplVerID` (1137) on
/// a FIXT.1.1 session (issue #67).
///
/// It is a required field of the FIXT.1.1 Logon, so an acceptor always
/// requires it. An initiator checks an acknowledgement's 1137 only when
/// present unless `strict_ack`
/// ([`SessionConfig::require_ack_default_appl_ver_id`]). A FIX 4.x session
/// checks nothing, whatever this says.
#[must_use]
pub const fn default_appl_ver_id_required(role: LogonRole, strict_ack: bool) -> bool {
    match role {
        LogonRole::Acceptor => true,
        LogonRole::Initiator => strict_ack,
    }
}

/// Whether a Logon's `ResetSeqNumFlag` (141) contradicts its `MsgSeqNum`
/// (34): FIX requires 34 = 1 on a Logon that carries 141 = Y, since the
/// reset and the number it arrives under have to describe the same stream.
#[must_use]
pub const fn reset_flag_contradicts(resets: bool, seq: u64) -> bool {
    resets && seq != 1
}

/// Whether an initiator's Logon declares `ResetSeqNumFlag` (141) = Y: when
/// configured to (`reset_on_logon`), or when an earlier session left a reset
/// owed (issue #111), so the counterparty restarts with it instead of
/// reading its `MsgSeqNum` 1 as too low.
#[must_use]
pub const fn initiator_resets(reset_on_logon: bool, reset_owed: bool) -> bool {
    reset_on_logon || reset_owed
}

/// Whether an acceptor starts a new stream on the Logon it accepted: when
/// the peer asks (141 = Y), when configured to (`reset_on_logon`), or when an
/// earlier session left a reset owed. Its acknowledgement then carries
/// 141 = Y, so the peer resets in lockstep.
#[must_use]
pub const fn acceptor_resets(inbound_reset: bool, reset_on_logon: bool, reset_owed: bool) -> bool {
    inbound_reset || reset_on_logon || reset_owed
}

/// Whether the intent to reset is made durable in the store before the
/// reset is acted on (ADR-0029): a crash between the two then leaves the
/// store's marker set, and the next session resets and declares it again.
/// Only a reset with a store to record it in.
#[must_use]
pub const fn owes_reset_durably(resets: bool, store_attached: bool) -> bool {
    resets && store_attached
}

/// The next sender number of an initiator that adopts a reset its
/// acknowledgement declared: its Logon, already on the wire, is message 1 of
/// the new stream, so rewinding to 1 would re-emit a number the counterparty
/// has seen.
pub const ADOPTED_RESET_NEXT_SENDER: u64 = 2;

/// The next target number an initiator that adopts its acknowledgement's
/// reset sets before the acknowledgement is consumed: the acknowledgement is
/// the acceptor's message 1.
pub const ADOPTED_RESET_NEXT_TARGET: u64 = 1;

/// The next target number the store is reset to when an initiator adopts
/// its acknowledgement's reset: one past the acknowledgement, which is
/// consumed before the session goes Active.
pub const ADOPTED_RESET_STORED_TARGET: u64 = 2;

/// What an acknowledgement's `ResetSeqNumFlag` (141) asks of an initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AckReset {
    /// The acknowledgement declares no reset.
    None,
    /// It echoes the reset this initiator's Logon declared: the store and
    /// the counters were reset before the Logon was sent.
    Echoed,
    /// The acceptor drove a reset the Logon did not declare. The initiator
    /// adopts it before the session goes Active: when a store is attached it
    /// owes the reset durably, then resets the store to
    /// ([`ADOPTED_RESET_NEXT_SENDER`], [`ADOPTED_RESET_STORED_TARGET`]) in
    /// one call, failing closed whatever the policy; in memory the target
    /// becomes [`ADOPTED_RESET_NEXT_TARGET`] and the sender
    /// [`ADOPTED_RESET_NEXT_SENDER`].
    Adopt,
}

/// Decides what an acknowledgement's 141 asks of an initiator whose Logon
/// declared a reset (`logon_reset`) or not.
#[must_use]
pub const fn decide_ack_reset(logon_reset: bool, ack_resets: bool) -> AckReset {
    match (ack_resets, logon_reset) {
        (false, _) => AckReset::None,
        (true, true) => AckReset::Echoed,
        (true, false) => AckReset::Adopt,
    }
}

/// Classifies the `MsgSeqNum` (34) of the counterparty's Logon (initiator:
/// its acknowledgement) under the reset rule both roles share.
///
/// In an exchange that resets the sequence, each side's Logon or
/// acknowledgement is message 1 of its new stream, so the counterparty's is
/// taken as its message 1 whatever positive number it carries (one that did
/// not ask for the reset is told to make it by this side's 141 = Y), and no
/// gap is opened for the old stream's numbers. 0 names no message, so it is
/// validated as usual (and refused as too low). Without a reset the number
/// is validated against `sequences`.
#[must_use]
pub fn classify_logon_seq(
    exchange_resets: bool,
    seq: u64,
    sequences: &SequenceManager,
) -> SequenceResult {
    if exchange_resets && seq > 0 {
        SequenceResult::Ok
    } else {
        sequences.validate_incoming(seq)
    }
}

/// What to do with a gap the counterparty's Logon opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogonGapAction {
    /// Both sides declared `NextExpectedMsgSeqNum` (789): this side's Logon
    /// named the first missing number, so the counterparty resends the gap
    /// on its own. The Logon is held, its number consumed once the gap is
    /// filled, and no `ResendRequest` (2) crosses the resend.
    Hold,
    /// Request the gap with a `ResendRequest` (2) as the reactor's first act.
    Request,
}

/// Decides how a gapped Logon is recovered: held when this session declares
/// 789 (`sends_next_expected`) and the counterparty declared a well-formed
/// one that the exchange did not discard, requested otherwise.
#[must_use]
pub const fn decide_logon_gap(sends_next_expected: bool, peer_declared: bool) -> LogonGapAction {
    if sends_next_expected && peer_declared {
        LogonGapAction::Hold
    } else {
        LogonGapAction::Request
    }
}

/// Resolves the heartbeat interval from the counterparty's `HeartBtInt`
/// (108), already parsed as `peer_secs`.
///
/// An acceptor adopts the interval the initiator requested and echoes it,
/// bounded by [`MAX_HEARTBEAT_INTERVAL_SECS`]: the value is
/// counterparty-controlled and drives every liveness timer. An initiator
/// honours the interval the acknowledgement confirmed through
/// [`negotiate_interval`], so its own `requested` value is always accepted.
///
/// # Errors
/// [`HeartbeatIntervalError`] for a value above the bound (for an
/// initiator, one that is not also its own request).
pub fn negotiate_logon_interval(
    role: LogonRole,
    requested: Duration,
    peer_secs: u64,
) -> Result<Duration, HeartbeatIntervalError> {
    match role {
        LogonRole::Initiator => negotiate_interval(requested, peer_secs),
        LogonRole::Acceptor => {
            if peer_secs > MAX_HEARTBEAT_INTERVAL_SECS {
                Err(HeartbeatIntervalError {
                    secs: peer_secs,
                    max: MAX_HEARTBEAT_INTERVAL_SECS,
                })
            } else {
                Ok(Duration::from_secs(peer_secs))
            }
        }
    }
}

/// The interval the heartbeat clock is rebuilt with, or `None` when the
/// negotiated interval is the one it already runs: rebuilding it then would
/// change nothing but the log.
#[must_use]
pub fn interval_change(current: Duration, negotiated: Duration) -> Option<Duration> {
    (negotiated != current).then_some(negotiated)
}

/// Why an acknowledgement's `HeartBtInt` (108) cannot be used. An initiator
/// refuses it with a session Reject (`RefTagID` (371) 108) and a Logout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AckHeartBtIntDefect {
    /// 108 is absent: it is a required field of the Logon.
    Missing,
    /// 108 is not a non-negative integer.
    Malformed,
    /// 108 is above [`MAX_HEARTBEAT_INTERVAL_SECS`] and not this side's own
    /// request.
    OutOfRange,
}

impl AckHeartBtIntDefect {
    /// The `SessionRejectReason` (373): 1 (required tag missing), 6
    /// (incorrect data format for value) or 5 (value is incorrect).
    #[must_use]
    pub const fn session_reject_reason(self) -> u32 {
        match self {
            Self::Missing => 1,
            Self::Malformed => 6,
            Self::OutOfRange => 5,
        }
    }
}

/// The `NextExpectedMsgSeqNum` (789) this session declares on its Logon or
/// acknowledgement, when it uses 789: its next expected inbound number.
///
/// Read at the moment the frame is built. On an initiator's Logon that is
/// the seeded target, 1 when the Logon declares a reset; on an acceptor's
/// acknowledgement it is read once the initiator's Logon was processed: the
/// Logon's number plus one in sequence, 2 after a reset, and the first
/// missing number when the Logon opened a gap (a gapped Logon is not
/// consumed).
#[must_use]
pub fn declared_next_expected(config: &SessionConfig, sequences: &SequenceManager) -> Option<u64> {
    config
        .send_next_expected_msg_seq_num
        .then(|| sequences.next_target_seq().value())
}

/// The value a counterparty that saw this session's one-sided reset is
/// expected to declare: its Logon was message 1 of the new stream, so it
/// expects 2 next.
pub const NEXT_EXPECTED_AFTER_RESET: u64 = 2;

/// What is left of the counterparty's 789 once the exchange's resets are
/// accounted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScreenedNextExpected {
    /// The counterparty declared no 789.
    Absent,
    /// The 789 describes the stream the session continues: plan it.
    Use(NonZeroU64),
    /// This side resets a stream the counterparty did not ask to reset, so
    /// its 789 may describe the discarded stream and is ignored.
    /// `matches_reset` says whether it equals [`NEXT_EXPECTED_AFTER_RESET`]:
    /// an initiator warns when it does not, since the acceptor then likely
    /// kept its old stream and will refuse the next message as too low.
    Ignored {
        /// The value declared.
        declared: NonZeroU64,
        /// The value is [`NEXT_EXPECTED_AFTER_RESET`].
        matches_reset: bool,
    },
}

impl ScreenedNextExpected {
    /// The value to plan, if any.
    #[must_use]
    pub const fn usable(self) -> Option<NonZeroU64> {
        match self {
            Self::Use(declared) => Some(declared),
            Self::Absent | Self::Ignored { .. } => None,
        }
    }
}

/// Screens a well-formed 789 the counterparty declared (`declared`, `None`
/// when absent) against the exchange's resets.
///
/// `this_side_resets` is the reset this side drives (initiator: its Logon
/// declared one; acceptor: it resets for any reason), and `peer_resets`
/// whether the counterparty's own frame carries 141 = Y. Only a reset this
/// side drives alone discards the stream the 789 describes; a counterparty
/// that declared the reset itself knew of it, so its 789 is still planned.
/// A malformed 789 never reaches this: it is refused whatever the resets.
#[must_use]
pub fn screen_next_expected(
    declared: Option<NonZeroU64>,
    this_side_resets: bool,
    peer_resets: bool,
) -> ScreenedNextExpected {
    match declared {
        None => ScreenedNextExpected::Absent,
        Some(declared) if this_side_resets && !peer_resets => ScreenedNextExpected::Ignored {
            declared,
            matches_reset: declared.get() == NEXT_EXPECTED_AFTER_RESET,
        },
        Some(declared) => ScreenedNextExpected::Use(declared),
    }
}

/// The numbers a counterparty's 789 is compared with (ADR-0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NextExpectedBasis {
    /// The `MsgSeqNum` of this session's own Logon (initiator) or
    /// acknowledgement (acceptor): nothing at or above it is replayed.
    pub own_logon_seq: u64,
    /// The next `MsgSeqNum` this session sends when the 789 is read: a value
    /// above it claims messages never sent.
    pub next_outbound: u64,
}

impl NextExpectedBasis {
    /// An initiator reading its acknowledgement's 789: its Logon was
    /// `logon_seq` and it sends `next_sender` next, unless the
    /// acknowledgement declares a reset, which makes the Logon message 1 and
    /// 2 the next.
    #[must_use]
    pub const fn initiator(ack_resets: bool, logon_seq: u64, next_sender: u64) -> Self {
        if ack_resets {
            Self {
                own_logon_seq: 1,
                next_outbound: ADOPTED_RESET_NEXT_SENDER,
            }
        } else {
            Self {
                own_logon_seq: logon_seq,
                next_outbound: next_sender,
            }
        }
    }

    /// An acceptor reading the Logon's 789 before it acknowledges: the
    /// acknowledgement takes `ack_seq`, which is also its next outbound.
    #[must_use]
    pub const fn acceptor(ack_seq: u64) -> Self {
        Self {
            own_logon_seq: ack_seq,
            next_outbound: ack_seq,
        }
    }

    /// An acceptor that resets: its acknowledgement is message 1. Known
    /// before the store is reset, so a 789 that cannot be honoured refuses
    /// the Logon before the reset is made.
    #[must_use]
    pub const fn acceptor_reset() -> Self {
        Self::acceptor(1)
    }
}

/// What a counterparty's `NextExpectedMsgSeqNum` (789) asks of this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NextExpectedPlan {
    /// The counterparty has every message this session sent before its own
    /// Logon or acknowledgement: nothing to resend.
    InStep,
    /// The counterparty missed the messages numbered `begin..end`: resend
    /// them once the session is Active, as if a `ResendRequest` (2) had asked
    /// for exactly that range.
    Replay {
        /// The first number to resend: the counterparty's 789.
        begin: u64,
        /// The first number **not** resent: this session's own Logon or
        /// acknowledgement.
        end: u64,
    },
}

impl NextExpectedPlan {
    /// The range to resend once Active, as `(first, exclusive end)`, or
    /// `None` when there is nothing to resend.
    #[must_use]
    pub const fn replay_range(self) -> Option<(u64, u64)> {
        match self {
            Self::InStep => None,
            Self::Replay { begin, end } => Some((begin, end)),
        }
    }
}

/// A counterparty's 789 above the next `MsgSeqNum` this session sends: it
/// claims to have received messages that were never sent, which this Logon
/// exchange cannot reconcile. The Logon is refused with a Logout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NextExpectedAhead {
    /// The value the counterparty declared.
    pub declared: u64,
    /// The next `MsgSeqNum` this session sends.
    pub next_outbound: u64,
}

/// Decides what a counterparty's `NextExpectedMsgSeqNum` (789) asks of this
/// session (ADR-0021). 789 never moves a counter.
///
/// - `declared > next_outbound`: [`NextExpectedAhead`].
/// - `declared < own_logon_seq`: [`NextExpectedPlan::Replay`] of
///   `declared..own_logon_seq`, which stops before this session's own Logon:
///   the counterparty has that message in hand as it reads the answer.
/// - otherwise [`NextExpectedPlan::InStep`].
///
/// # Errors
/// [`NextExpectedAhead`] as above.
pub const fn plan_next_expected(
    declared: NonZeroU64,
    basis: NextExpectedBasis,
) -> Result<NextExpectedPlan, NextExpectedAhead> {
    let declared = declared.get();
    if declared > basis.next_outbound {
        return Err(NextExpectedAhead {
            declared,
            next_outbound: basis.next_outbound,
        });
    }
    if declared < basis.own_logon_seq {
        return Ok(NextExpectedPlan::Replay {
            begin: declared,
            end: basis.own_logon_seq,
        });
    }
    Ok(NextExpectedPlan::InStep)
}

/// Where a session's starting counters come from, highest priority first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SeedSource {
    /// The exchange resets: both counters start at 1, and an attached store
    /// is reset to 1/1 in one call (keeping the old messages would file two
    /// streams under the same numbers). Fails closed whatever the policy.
    Reset,
    /// An explicit initial seed, which outranks the store
    /// ([`seed_from_initial`]). With `check_store` the store is refreshed
    /// first and a sender seed below its next sender number is refused
    /// ([`initial_below_store`]).
    Initial {
        /// A store is attached under a policy that closes the session on a
        /// store failure.
        check_store: bool,
    },
    /// The store's own counters, refreshed from its medium first
    /// ([`seed_from_store`]).
    Store,
    /// A fresh session at 1/1.
    Fresh,
}

/// Decides where a session's counters come from.
#[must_use]
pub const fn decide_seed_source(
    reset: bool,
    has_initial: bool,
    store_attached: bool,
    closes_session: bool,
) -> SeedSource {
    if reset {
        SeedSource::Reset
    } else if has_initial {
        SeedSource::Initial {
            check_store: store_attached && closes_session,
        }
    } else if store_attached {
        SeedSource::Store
    } else {
        SeedSource::Fresh
    }
}

/// The counters an explicit `(sender, target)` seed starts a session from.
///
/// # Errors
/// The counter that is zero, sender first: FIX numbers messages from 1, and
/// a `MsgSeqNum` (34) of 0 is rejected by every conforming counterparty. A
/// zero seed is refused, never raised to 1.
pub const fn seed_from_initial(
    (sender, target): (u64, u64),
) -> Result<SequenceManager, SequenceCounter> {
    let Some(sender) = NonZeroU64::new(sender) else {
        return Err(SequenceCounter::Sender);
    };
    let Some(target) = NonZeroU64::new(target) else {
        return Err(SequenceCounter::Target);
    };
    Ok(SequenceManager::with_initial(sender, target))
}

/// Whether an explicit sender seed is below the store's next sender number,
/// which would reuse a `MsgSeqNum` already sent: refused under a policy that
/// closes the session on a store failure.
#[must_use]
pub const fn initial_below_store(seeded_sender: u64, stored_sender: u64) -> bool {
    seeded_sender < stored_sender
}

/// The counters a session starts from when they come from the store.
#[derive(Debug)]
pub struct StoreSeed {
    /// The counters, each floored at 1.
    pub sequences: SequenceManager,
    /// The store holds the sender value, so it need not be written back.
    pub sender_held: bool,
    /// The store holds the target value, so it need not be written back.
    pub target_held: bool,
}

/// The counters a session starts from the store's `(sender, target)`.
///
/// A store reporting 0 reports a number that names no message: it is
/// floored at 1 rather than numbering a message 0, and a floored value is
/// not one the store holds, so it is written once the session runs.
#[must_use]
pub const fn seed_from_store(sender: u64, target: u64) -> StoreSeed {
    let (sender_value, sender_held) = match NonZeroU64::new(sender) {
        Some(value) => (value, true),
        None => (NonZeroU64::MIN, false),
    };
    let (target_value, target_held) = match NonZeroU64::new(target) {
        Some(value) => (value, true),
        None => (NonZeroU64::MIN, false),
    };
    StoreSeed {
        sequences: SequenceManager::with_initial(sender_value, target_value),
        sender_held,
        target_held,
    }
}

/// Whether an initiator's explicit seed is used, and so must be checked for
/// zero before anything is dialled: a Logon that declares a reset
/// ([`initiator_resets`]) ignores the seed entirely.
#[must_use]
pub const fn initial_seed_applies(reset_on_logon: bool, reset_owed: bool) -> bool {
    !initiator_resets(reset_on_logon, reset_owed)
}

/// The counters a store-less acceptor numbers its refusal of an
/// unauthenticated peer from ([`LogonRefusal::Provisional`]): the explicit
/// seed when one is used, otherwise 1/1, also for a zero seed (which the
/// session refuses once the peer is authenticated).
#[must_use]
pub fn provisional_counters(initial: Option<(u64, u64)>, reset_on_logon: bool) -> SequenceManager {
    match initial {
        Some(initial) if !reset_on_logon => {
            seed_from_initial(initial).unwrap_or_else(|_| SequenceManager::new())
        }
        _ => SequenceManager::new(),
    }
}

/// The inbound span `(first, last)` the start report of issue #105
/// (ADR-0030) names: the numbers the previous session accepted above the
/// store's application `watermark`, up to `next_target - 1`.
///
/// `None` when there is none: a watermark of 0 (none recorded), one that
/// covers every number below `next_target`, or one above it (a stale
/// watermark a reset outlived).
#[must_use]
pub fn inbound_loss_span(watermark: u64, next_target: u64) -> Option<(u64, u64)> {
    if watermark == 0 {
        return None;
    }
    let first = watermark.checked_add(1)?;
    let last = next_target.checked_sub(1)?;
    (first <= last).then_some((first, last))
}

/// Whether a Logon exchange's numbers are compared for the mismatch report
/// (issue #80, ADR-0015): never for an exchange that carries
/// `ResetSeqNumFlag` (141) = Y in either direction, since a reset discards
/// both histories by agreement.
#[must_use]
pub const fn mismatch_report_applies(this_side_resets: bool, peer_resets: bool) -> bool {
    !this_side_resets && !peer_resets
}

/// The effective startup counters a role compares the counterparty's Logon
/// with: the numbers the session actually starts from, after the choice
/// between store, seed and reset. What the store held is reported beside
/// them, never compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogonCounters {
    /// The next sender number the session started from: the number of its
    /// own Logon or acknowledgement.
    pub next_sender: u64,
    /// The next target number the session started from: the number it
    /// expected the counterparty's Logon to carry.
    pub next_target: u64,
    /// The next number this side sends after its own Logon, as ADR-0021
    /// reads it in each role.
    pub next_outbound: u64,
}

impl LogonCounters {
    /// An initiator: its Logon was `logon_seq`, it expected the
    /// acknowledgement at `startup_target`, and it sends `next_sender` next.
    #[must_use]
    pub const fn initiator(logon_seq: u64, startup_target: u64, next_sender: u64) -> Self {
        Self {
            next_sender: logon_seq,
            next_target: startup_target,
            next_outbound: next_sender,
        }
    }

    /// An acceptor whose counters are chosen and whose acknowledgement is
    /// not sent yet: the acknowledgement is both its own Logon number and
    /// its next outbound.
    #[must_use]
    pub fn acceptor(sequences: &SequenceManager) -> Self {
        let next_sender = sequences.next_sender_seq().value();
        Self {
            next_sender,
            next_target: sequences.next_target_seq().value(),
            next_outbound: next_sender,
        }
    }
}

/// How the counterparty's Logon `MsgSeqNum` (34) differs from the effective
/// next target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogonInboundMismatch {
    /// The counterparty sent `first..=last` that this side has no record of.
    Gap {
        /// The effective next target.
        first: u64,
        /// The Logon's number minus one.
        last: u64,
    },
    /// The counterparty is behind this side's record of its stream.
    TooLow {
        /// The number the Logon carried.
        received: u64,
        /// The effective next target.
        expected: u64,
    },
}

/// How the counterparty's 789 relates to this side's outbound stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogonOutboundComparison {
    /// No usable 789 was declared.
    NotDeclared,
    /// The 789 lies between this side's own Logon number and its next
    /// outbound.
    Consistent {
        /// The value declared.
        declared: u64,
    },
    /// The 789 is below this side's own Logon: the counterparty missed
    /// `first..=last`.
    PeerMissed {
        /// The value declared.
        first: u64,
        /// This side's own Logon number minus one.
        last: u64,
    },
    /// The 789 is above this side's next outbound.
    PeerAhead {
        /// The value declared.
        declared: u64,
        /// This side's next outbound.
        next_outbound: u64,
    },
}

impl LogonOutboundComparison {
    /// Whether this is a disagreement.
    #[must_use]
    pub const fn is_mismatch(self) -> bool {
        matches!(self, Self::PeerMissed { .. } | Self::PeerAhead { .. })
    }
}

/// The comparison of a Logon exchange with the effective startup counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogonSequenceComparison {
    /// The inbound comparison, `None` when the Logon carried the expected
    /// number.
    pub inbound: Option<LogonInboundMismatch>,
    /// The outbound comparison.
    pub outbound: LogonOutboundComparison,
}

impl LogonSequenceComparison {
    /// Whether at least one comparison differs: only then is a report made.
    #[must_use]
    pub const fn is_mismatch(&self) -> bool {
        self.inbound.is_some() || self.outbound.is_mismatch()
    }
}

/// Compares the `MsgSeqNum` (34) of the counterparty's Logon (initiator:
/// its acknowledgement) with the effective `next_target`: `None` when they
/// agree.
#[must_use]
pub fn compare_logon_inbound(
    peer_logon_seq: u64,
    next_target: u64,
) -> Option<LogonInboundMismatch> {
    match peer_logon_seq.cmp(&next_target) {
        std::cmp::Ordering::Equal => None,
        std::cmp::Ordering::Less => Some(LogonInboundMismatch::TooLow {
            received: peer_logon_seq,
            expected: next_target,
        }),
        // peer_logon_seq > next_target >= 0, so it is >= 1.
        std::cmp::Ordering::Greater => match peer_logon_seq.checked_sub(1) {
            Some(last) => Some(LogonInboundMismatch::Gap {
                first: next_target,
                last,
            }),
            None => {
                debug_assert!(false, "a Logon number above the target is >= 1");
                None
            }
        },
    }
}

/// Compares the counterparty's 789 (`None` when not declared or not used)
/// with this side's own Logon number and next outbound, with the boundaries
/// [`plan_next_expected`] uses.
#[must_use]
pub fn compare_logon_outbound(
    peer_next_expected: Option<u64>,
    own_logon_seq: u64,
    next_outbound: u64,
) -> LogonOutboundComparison {
    let Some(declared) = peer_next_expected else {
        return LogonOutboundComparison::NotDeclared;
    };
    if declared > next_outbound {
        return LogonOutboundComparison::PeerAhead {
            declared,
            next_outbound,
        };
    }
    if declared < own_logon_seq {
        // declared < own_logon_seq, so own_logon_seq >= 1.
        return match own_logon_seq.checked_sub(1) {
            Some(last) => LogonOutboundComparison::PeerMissed {
                first: declared,
                last,
            },
            None => {
                debug_assert!(false, "own Logon number above a declared 789 is >= 1");
                LogonOutboundComparison::Consistent { declared }
            }
        };
    }
    LogonOutboundComparison::Consistent { declared }
}

/// Compares a Logon exchange with the effective startup `counters`: the
/// counterparty's Logon number `peer_logon_seq` against the next target
/// ([`compare_logon_inbound`]), and its 789 `peer_next_expected` (when this
/// session uses 789 and the value is well formed) against this side's own
/// Logon and next outbound ([`compare_logon_outbound`]). Nothing moves.
#[must_use]
pub fn compare_logon_sequences(
    counters: LogonCounters,
    peer_logon_seq: u64,
    peer_next_expected: Option<u64>,
) -> LogonSequenceComparison {
    LogonSequenceComparison {
        inbound: compare_logon_inbound(peer_logon_seq, counters.next_target),
        outbound: compare_logon_outbound(
            peer_next_expected,
            counters.next_sender,
            counters.next_outbound,
        ),
    }
}

/// The instant a wait for a Logon (or its acknowledgement) started at
/// `started` gives up, or `None` when `logon_timeout` reaches past what an
/// [`Instant`] can represent, which bounds nothing.
#[must_use]
pub fn logon_deadline(started: Instant, logon_timeout: Duration) -> Option<Instant> {
    started.checked_add(logon_timeout)
}

/// Whether a wait for a Logon started at `started` has run `logon_timeout`
/// by `now`. A `now` earlier than `started` counts as no time elapsed.
#[must_use]
pub fn logon_timed_out(started: Instant, now: Instant, logon_timeout: Duration) -> bool {
    now.checked_duration_since(started)
        .unwrap_or(Duration::ZERO)
        >= logon_timeout
}

/// The deadline of an initiator's wait for its acknowledgement, from the
/// instant its Logon was sent ([`Session::sent_at`]).
#[must_use]
pub fn logon_ack_deadline(
    session: &Session<LogonSent>,
    logon_timeout: Duration,
) -> Option<Instant> {
    logon_deadline(session.sent_at(), logon_timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Disconnected;
    use ironfix_core::types::CompId;

    #[track_caller]
    fn nz(value: u64) -> NonZeroU64 {
        match NonZeroU64::new(value) {
            Some(value) => value,
            None => panic!("test numbers are positive"),
        }
    }

    #[track_caller]
    fn counters(sender: u64, target: u64) -> SequenceManager {
        match seed_from_initial((sender, target)) {
            Ok(sequences) => sequences,
            Err(counter) => panic!("test seed is positive: {counter:?}"),
        }
    }

    fn config(send_789: bool) -> SessionConfig {
        let comp = |value: &str| match CompId::new(value) {
            Ok(id) => id,
            Err(err) => panic!("test CompID is valid: {err}"),
        };
        let mut config = SessionConfig::new(comp("A"), comp("B"), "FIX.4.4");
        config.send_next_expected_msg_seq_num = send_789;
        config
    }

    // ---------------------------------------------------------------
    // Test-only transcriptions of the engine rules this stage replaced.
    // ---------------------------------------------------------------

    /// The acceptor's old refusal routing: `refuse_unauthenticated` (with
    /// its `before_admission` flag) and `refuse_authenticated`.
    fn old_acceptor_refusal(
        authenticated: bool,
        before_admission: bool,
        store: bool,
        live: bool,
    ) -> LogonRefusal {
        if authenticated {
            return LogonRefusal::Filed;
        }
        if before_admission && live {
            return LogonRefusal::SilentSessionLive;
        }
        if store {
            return LogonRefusal::SilentStoreAttached;
        }
        LogonRefusal::Provisional
    }

    /// The old `next_expected::plan`.
    fn old_plan(
        declared: u64,
        own_logon_seq: u64,
        next_outbound: u64,
    ) -> Result<Option<(u64, u64)>, (u64, u64)> {
        if declared > next_outbound {
            return Err((declared, next_outbound));
        }
        if declared < own_logon_seq {
            return Ok(Some((declared, own_logon_seq)));
        }
        Ok(None)
    }

    /// The old `seed_session` branch order, as (source, check_store).
    fn old_seed_branch(reset: bool, initial: bool, store: bool, closes: bool) -> (u8, bool) {
        if reset {
            return (0, false);
        }
        if initial {
            return (1, store && closes);
        }
        if store { (2, false) } else { (3, false) }
    }

    /// The old `InboundLoss::between`.
    fn old_between(watermark: u64, next_target: u64) -> Option<(u64, u64)> {
        if watermark == 0 {
            return None;
        }
        let first = watermark.checked_add(1)?;
        let last = next_target.checked_sub(1)?;
        (first <= last).then_some((first, last))
    }

    /// The old initiator 789 filter and acceptor 789 filter, merged by
    /// their shared shape: `Some(Some(v))` used, `Some(None)` ignored.
    fn old_screen(declared: Option<u64>, ours: bool, theirs: bool) -> Option<Option<u64>> {
        match declared {
            Some(_) if ours && !theirs => Some(None),
            Some(value) => Some(Some(value)),
            None => None,
        }
    }

    const EDGES: [u64; 9] = [0, 1, 2, 3, 5, 6, 7, u64::MAX - 1, u64::MAX];

    #[test]
    fn test_refusal_initiator_always_files() {
        for stage in [
            LogonStage::BeforeAdmission,
            LogonStage::Admitted,
            LogonStage::Authenticated,
        ] {
            for store in [false, true] {
                for live in [false, true] {
                    assert_eq!(
                        decide_logon_refusal(LogonRole::Initiator, stage, store, live),
                        LogonRefusal::Filed
                    );
                }
            }
        }
    }

    #[test]
    fn test_refusal_acceptor_matches_the_old_routing() {
        for (stage, authenticated, before) in [
            (LogonStage::BeforeAdmission, false, true),
            (LogonStage::Admitted, false, false),
            (LogonStage::Authenticated, true, false),
        ] {
            for store in [false, true] {
                for live in [false, true] {
                    assert_eq!(
                        decide_logon_refusal(LogonRole::Acceptor, stage, store, live),
                        old_acceptor_refusal(authenticated, before, store, live),
                        "{stage:?} store={store} live={live}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_refusal_admitted_ignores_liveness() {
        assert_eq!(
            decide_logon_refusal(LogonRole::Acceptor, LogonStage::Admitted, false, true),
            LogonRefusal::Provisional
        );
        assert_eq!(
            decide_logon_refusal(LogonRole::Acceptor, LogonStage::BeforeAdmission, true, true),
            LogonRefusal::SilentSessionLive
        );
    }

    #[test]
    fn test_default_appl_ver_id_rule_per_role() {
        assert!(default_appl_ver_id_required(LogonRole::Acceptor, false));
        assert!(default_appl_ver_id_required(LogonRole::Acceptor, true));
        assert!(!default_appl_ver_id_required(LogonRole::Initiator, false));
        assert!(default_appl_ver_id_required(LogonRole::Initiator, true));
    }

    #[test]
    fn test_reset_flag_contradiction() {
        for seq in EDGES {
            assert_eq!(reset_flag_contradicts(true, seq), seq != 1, "{seq}");
            assert!(!reset_flag_contradicts(false, seq));
        }
    }

    #[test]
    fn test_reset_decisions_match_the_old_expressions() {
        for a in [false, true] {
            for b in [false, true] {
                assert_eq!(initiator_resets(a, b), a || b);
                assert_eq!(initial_seed_applies(a, b), !a && !b);
                assert_eq!(owes_reset_durably(a, b), a && b);
                assert_eq!(mismatch_report_applies(a, b), !a && !b);
                for c in [false, true] {
                    assert_eq!(acceptor_resets(a, b, c), a || b || c);
                }
            }
        }
    }

    #[test]
    fn test_ack_reset() {
        assert_eq!(decide_ack_reset(false, false), AckReset::None);
        assert_eq!(decide_ack_reset(true, false), AckReset::None);
        assert_eq!(decide_ack_reset(true, true), AckReset::Echoed);
        assert_eq!(decide_ack_reset(false, true), AckReset::Adopt);
    }

    #[test]
    fn test_classify_logon_seq_reset_rule() {
        let sequences = counters(5, 9);
        for seq in [1, 2, 8, 9, 10, u64::MAX] {
            assert_eq!(
                classify_logon_seq(true, seq, &sequences),
                SequenceResult::Ok
            );
        }
        // 0 is validated as usual under a reset too.
        assert_eq!(
            classify_logon_seq(true, 0, &sequences),
            sequences.validate_incoming(0)
        );
        for seq in EDGES {
            assert_eq!(
                classify_logon_seq(false, seq, &sequences),
                sequences.validate_incoming(seq)
            );
        }
    }

    #[test]
    fn test_logon_gap_action() {
        assert_eq!(decide_logon_gap(true, true), LogonGapAction::Hold);
        assert_eq!(decide_logon_gap(true, false), LogonGapAction::Request);
        assert_eq!(decide_logon_gap(false, true), LogonGapAction::Request);
        assert_eq!(decide_logon_gap(false, false), LogonGapAction::Request);
    }

    #[test]
    fn test_negotiate_logon_interval_per_role() {
        let requested = Duration::from_secs(30);
        let max = MAX_HEARTBEAT_INTERVAL_SECS;
        for secs in [0, 1, 30, max, max + 1, u64::MAX] {
            assert_eq!(
                negotiate_logon_interval(LogonRole::Initiator, requested, secs),
                negotiate_interval(requested, secs)
            );
            let acceptor = negotiate_logon_interval(LogonRole::Acceptor, requested, secs);
            if secs > max {
                assert!(acceptor.is_err(), "{secs}");
            } else {
                assert_eq!(acceptor, Ok(Duration::from_secs(secs)));
            }
        }
        // An initiator always accepts its own request, even above the bound.
        let large = Duration::from_secs(max + 5);
        assert_eq!(
            negotiate_logon_interval(LogonRole::Initiator, large, max + 5),
            Ok(large)
        );
    }

    #[test]
    fn test_interval_change() {
        let thirty = Duration::from_secs(30);
        assert_eq!(interval_change(thirty, thirty), None);
        assert_eq!(
            interval_change(thirty, Duration::from_secs(10)),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            interval_change(thirty, Duration::ZERO),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn test_ack_heartbtint_reject_codes() {
        assert_eq!(AckHeartBtIntDefect::Missing.session_reject_reason(), 1);
        assert_eq!(AckHeartBtIntDefect::Malformed.session_reject_reason(), 6);
        assert_eq!(AckHeartBtIntDefect::OutOfRange.session_reject_reason(), 5);
    }

    #[test]
    fn test_declared_next_expected_reads_the_target_when_used() {
        let sequences = counters(4, 7);
        assert_eq!(declared_next_expected(&config(true), &sequences), Some(7));
        assert_eq!(declared_next_expected(&config(false), &sequences), None);
    }

    #[test]
    fn test_screen_next_expected_matches_the_old_filters() {
        for declared in [None, Some(1), Some(2), Some(3), Some(u64::MAX)] {
            for ours in [false, true] {
                for theirs in [false, true] {
                    let screened = screen_next_expected(declared.map(nz), ours, theirs);
                    let old = old_screen(declared, ours, theirs);
                    match (screened, old) {
                        (ScreenedNextExpected::Absent, None) => {}
                        (ScreenedNextExpected::Use(value), Some(Some(old))) => {
                            assert_eq!(value.get(), old);
                        }
                        (
                            ScreenedNextExpected::Ignored {
                                declared: value,
                                matches_reset,
                            },
                            Some(None),
                        ) => assert_eq!(matches_reset, value.get() == 2),
                        other => panic!("diverged: {other:?}"),
                    }
                    assert_eq!(
                        screened.usable().map(NonZeroU64::get),
                        old.flatten(),
                        "{declared:?} {ours} {theirs}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_plan_matches_the_old_plan_over_a_grid() {
        let values = [1, 2, 3, 4, 5, 6, 7, 100, u64::MAX - 1, u64::MAX];
        for declared in values {
            for own in [0, 1, 2, 5, 6, 100, u64::MAX] {
                for next in [0, 1, 2, 5, 6, 7, 100, u64::MAX] {
                    let basis = NextExpectedBasis {
                        own_logon_seq: own,
                        next_outbound: next,
                    };
                    let new = plan_next_expected(nz(declared), basis)
                        .map(NextExpectedPlan::replay_range)
                        .map_err(|ahead| (ahead.declared, ahead.next_outbound));
                    assert_eq!(
                        new,
                        old_plan(declared, own, next),
                        "{declared} {own} {next}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_plan_cases_of_each_role() {
        // Acceptor, ack 5.
        let basis = NextExpectedBasis::acceptor(5);
        assert_eq!(
            plan_next_expected(nz(5), basis),
            Ok(NextExpectedPlan::InStep)
        );
        assert_eq!(
            plan_next_expected(nz(3), basis),
            Ok(NextExpectedPlan::Replay { begin: 3, end: 5 })
        );
        assert_eq!(
            plan_next_expected(nz(6), basis),
            Err(NextExpectedAhead {
                declared: 6,
                next_outbound: 5
            })
        );
        // Acceptor that resets: only 1 is in step.
        assert_eq!(
            plan_next_expected(nz(1), NextExpectedBasis::acceptor_reset()),
            Ok(NextExpectedPlan::InStep)
        );
        assert!(plan_next_expected(nz(2), NextExpectedBasis::acceptor_reset()).is_err());
        // Initiator, Logon 5, next 6; and after the ack's reset.
        let basis = NextExpectedBasis::initiator(false, 5, 6);
        assert_eq!(
            plan_next_expected(nz(2), basis),
            Ok(NextExpectedPlan::Replay { begin: 2, end: 5 })
        );
        assert!(plan_next_expected(nz(7), basis).is_err());
        let reset = NextExpectedBasis::initiator(true, 5, 6);
        assert_eq!(
            reset,
            NextExpectedBasis {
                own_logon_seq: 1,
                next_outbound: 2
            }
        );
        assert_eq!(
            plan_next_expected(nz(2), reset),
            Ok(NextExpectedPlan::InStep)
        );
        assert!(plan_next_expected(nz(3), reset).is_err());
    }

    #[test]
    fn test_seed_source_matches_the_old_branch_order() {
        for reset in [false, true] {
            for initial in [false, true] {
                for store in [false, true] {
                    for closes in [false, true] {
                        let new = match decide_seed_source(reset, initial, store, closes) {
                            SeedSource::Reset => (0, false),
                            SeedSource::Initial { check_store } => (1, check_store),
                            SeedSource::Store => (2, false),
                            SeedSource::Fresh => (3, false),
                        };
                        assert_eq!(new, old_seed_branch(reset, initial, store, closes));
                    }
                }
            }
        }
    }

    #[test]
    fn test_seed_from_initial_refuses_zero_sender_first() {
        assert!(matches!(
            seed_from_initial((0, 0)),
            Err(SequenceCounter::Sender)
        ));
        assert!(matches!(
            seed_from_initial((0, 3)),
            Err(SequenceCounter::Sender)
        ));
        assert!(matches!(
            seed_from_initial((3, 0)),
            Err(SequenceCounter::Target)
        ));
        let sequences = counters(7, u64::MAX);
        assert_eq!(sequences.next_sender_seq().value(), 7);
        assert_eq!(sequences.next_target_seq().value(), u64::MAX);
    }

    #[test]
    fn test_initial_below_store() {
        assert!(initial_below_store(4, 5));
        assert!(!initial_below_store(5, 5));
        assert!(!initial_below_store(6, 5));
    }

    #[test]
    fn test_seed_from_store_floors_zero_and_marks_it_unheld() {
        let seed = seed_from_store(0, 0);
        assert_eq!(seed.sequences.next_sender_seq().value(), 1);
        assert_eq!(seed.sequences.next_target_seq().value(), 1);
        assert!(!seed.sender_held && !seed.target_held);
        let seed = seed_from_store(9, 0);
        assert_eq!(seed.sequences.next_sender_seq().value(), 9);
        assert!(seed.sender_held && !seed.target_held);
        let seed = seed_from_store(u64::MAX, 3);
        assert_eq!(seed.sequences.next_sender_seq().value(), u64::MAX);
        assert_eq!(seed.sequences.next_target_seq().value(), 3);
        assert!(seed.sender_held && seed.target_held);
    }

    #[test]
    fn test_provisional_counters() {
        let at = |initial, reset| {
            let sequences = provisional_counters(initial, reset);
            (
                sequences.next_sender_seq().value(),
                sequences.next_target_seq().value(),
            )
        };
        assert_eq!(at(None, false), (1, 1));
        assert_eq!(at(Some((4, 9)), false), (4, 9));
        assert_eq!(at(Some((4, 9)), true), (1, 1));
        assert_eq!(at(Some((0, 9)), false), (1, 1));
        assert_eq!(at(Some((4, 0)), false), (1, 1));
    }

    #[test]
    fn test_inbound_loss_span_matches_the_old_between() {
        for watermark in EDGES {
            for target in EDGES {
                assert_eq!(
                    inbound_loss_span(watermark, target),
                    old_between(watermark, target),
                    "{watermark} {target}"
                );
            }
        }
        assert_eq!(inbound_loss_span(4, 8), Some((5, 7)));
        assert_eq!(inbound_loss_span(7, 8), None);
        assert_eq!(inbound_loss_span(50, 2), None);
    }

    #[test]
    fn test_logon_counters_per_role() {
        assert_eq!(
            LogonCounters::initiator(5, 9, 6),
            LogonCounters {
                next_sender: 5,
                next_target: 9,
                next_outbound: 6
            }
        );
        let sequences = counters(4, 8);
        assert_eq!(
            LogonCounters::acceptor(&sequences),
            LogonCounters {
                next_sender: 4,
                next_target: 8,
                next_outbound: 4
            }
        );
    }

    #[test]
    fn test_compare_logon_sequences() {
        let counters = LogonCounters::initiator(5, 9, 6);
        let same = compare_logon_sequences(counters, 9, None);
        assert!(!same.is_mismatch());
        assert_eq!(same.outbound, LogonOutboundComparison::NotDeclared);
        assert_eq!(
            compare_logon_sequences(counters, 12, None).inbound,
            Some(LogonInboundMismatch::Gap { first: 9, last: 11 })
        );
        assert_eq!(
            compare_logon_sequences(counters, 3, None).inbound,
            Some(LogonInboundMismatch::TooLow {
                received: 3,
                expected: 9
            })
        );
        assert_eq!(
            compare_logon_sequences(counters, 9, Some(2)).outbound,
            LogonOutboundComparison::PeerMissed { first: 2, last: 4 }
        );
        assert_eq!(
            compare_logon_sequences(counters, 9, Some(7)).outbound,
            LogonOutboundComparison::PeerAhead {
                declared: 7,
                next_outbound: 6
            }
        );
        let consistent = compare_logon_sequences(counters, 9, Some(6));
        assert_eq!(
            consistent.outbound,
            LogonOutboundComparison::Consistent { declared: 6 }
        );
        assert!(!consistent.is_mismatch());
    }

    #[test]
    fn test_compare_logon_sequences_agrees_with_the_plan() {
        // The outbound comparison and the 789 plan share their boundaries.
        for declared in [1, 2, 4, 5, 6, 7, u64::MAX] {
            for (own, next) in [(1, 1), (1, 2), (5, 5), (5, 6), (u64::MAX, u64::MAX)] {
                let counters = LogonCounters {
                    next_sender: own,
                    next_target: 1,
                    next_outbound: next,
                };
                let outbound = compare_logon_sequences(counters, 1, Some(declared)).outbound;
                let plan = plan_next_expected(
                    nz(declared),
                    NextExpectedBasis {
                        own_logon_seq: own,
                        next_outbound: next,
                    },
                );
                match (outbound, plan) {
                    (LogonOutboundComparison::PeerAhead { .. }, Err(_))
                    | (LogonOutboundComparison::Consistent { .. }, Ok(NextExpectedPlan::InStep)) => {
                    }
                    (
                        LogonOutboundComparison::PeerMissed { first, last },
                        Ok(NextExpectedPlan::Replay { begin, end }),
                    ) => {
                        assert_eq!(first, begin);
                        assert_eq!(last.checked_add(1), Some(end));
                    }
                    other => panic!("diverged for {declared} {own} {next}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn test_compare_logon_sequences_boundaries_do_not_underflow() {
        let counters = LogonCounters {
            next_sender: 1,
            next_target: 0,
            next_outbound: 1,
        };
        let comparison = compare_logon_sequences(counters, 1, Some(1));
        assert_eq!(
            comparison.inbound,
            Some(LogonInboundMismatch::Gap { first: 0, last: 0 })
        );
        assert_eq!(
            comparison.outbound,
            LogonOutboundComparison::Consistent { declared: 1 }
        );
    }

    #[test]
    fn test_logon_deadline_and_timeout_with_synthetic_time() {
        let t0 = Instant::now();
        let timeout = Duration::from_secs(10);
        assert_eq!(logon_deadline(t0, timeout), t0.checked_add(timeout));
        assert!(logon_deadline(t0, Duration::MAX).is_none());
        assert!(!logon_timed_out(t0, t0, timeout));
        assert!(!logon_timed_out(t0, t0 + Duration::from_secs(9), timeout));
        assert!(logon_timed_out(t0, t0 + timeout, timeout));
        assert!(logon_timed_out(t0, t0, Duration::ZERO));
        // A now before the start is no time elapsed.
        let later = t0 + Duration::from_secs(5);
        assert!(!logon_timed_out(later, t0, Duration::from_secs(1)));
    }

    #[test]
    fn test_logon_ack_deadline_runs_from_sent_at() {
        let t0 = Instant::now();
        let at = t0 + Duration::from_secs(3);
        let session = Session::<Disconnected>::new("S".to_string())
            .connect()
            .send_logon(at);
        let timeout = Duration::from_secs(10);
        assert_eq!(
            logon_ack_deadline(&session, timeout),
            at.checked_add(timeout)
        );
        let _ = session.on_logon_reject();
    }
}
