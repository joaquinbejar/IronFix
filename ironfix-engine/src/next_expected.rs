/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! `NextExpectedMsgSeqNum` (789) on the Logon exchange: reading the value a
//! counterparty declares, and deciding what it asks of this session.
//!
//! FIX.4.4 and FIXT.1.1 define 789 on the Logon as the next `MsgSeqNum` the
//! sender expects to receive. With
//! [`SessionConfig::send_next_expected_msg_seq_num`](ironfix_session::SessionConfig::send_next_expected_msg_seq_num)
//! set, both engines declare it and act on the counterparty's:
//!
//! - **What this session declares.** Its own next expected inbound
//!   `MsgSeqNum`. On an initiator's Logon that is the next number it expects
//!   from the acceptor, 1 when the Logon declares `ResetSeqNumFlag` (141) = Y.
//!   On an acceptor's acknowledgement it is computed once the initiator's
//!   Logon has been processed: the Logon's number plus one when it was in
//!   sequence, 2 after a reset (the Logon is message 1 of the new stream), and
//!   the first missing number when the Logon opened a gap, since a gapped
//!   Logon is not consumed.
//! - **What the counterparty's value asks.** [`plan`] compares it with the
//!   `MsgSeqNum` of this session's own Logon or acknowledgement and with the
//!   next `MsgSeqNum` this session sends. A value above the next number this
//!   session sends claims messages that were never sent: the Logon exchange
//!   cannot be reconciled and is refused with a Logout. A value below this
//!   session's own Logon names messages the counterparty missed: they are
//!   resent once the session is Active, through the same replay a
//!   `ResendRequest` (2) gets (application messages from the store with
//!   `PossDupFlag` (43) = Y and `OrigSendingTime` (122), everything else
//!   gap-filled). Anything in between asks for nothing.
//!
//! The replayed range stops **before** this session's own Logon or
//! acknowledgement. The counterparty has that message in hand as it reads
//! the 789 answer: a counterparty that declared 789 holds the gapped Logon and
//! consumes its number once the gap below it is filled, as IronFix and
//! QuickFIX/C++ do, and one that did not asks for it with a `ResendRequest`,
//! whose answer gap-fills it. Nothing is ever replayed at or above that
//! number.
//!
//! The other half of the exchange lives in the reactor: when this session
//! declared 789 and the counterparty's Logon or acknowledgement carries a
//! well-formed 789 and arrives with a gap below it, no `ResendRequest` is sent,
//! since the counterparty resends that gap on its own; the Logon is held and
//! its number consumed once the gap is filled.
//!
//! Every decision here is synchronous, takes the counters it compares as
//! parameters and reads no clock (ADR-0002). 789 never moves a sequence
//! counter: it only triggers a replay or refuses the Logon.

use crate::application::RejectReason;
use crate::wire::{self, FieldOccurrence};
use ironfix_core::message::RawMessage;
use std::num::NonZeroU64;

/// `NextExpectedMsgSeqNum` (789): on a Logon, the next `MsgSeqNum` the sender
/// expects to receive (FIX.4.4, FIXT.1.1).
pub(crate) const NEXT_EXPECTED_MSG_SEQ_NUM: u32 = 789;

/// Longest 789 value echoed in a log line, a Reject or a Logout `Text` (58).
/// The value is counterparty-controlled, so it is bounded; a legal one is at
/// most 20 digits.
const MAX_ECHOED_VALUE: usize = 32;

/// Why a counterparty's `NextExpectedMsgSeqNum` (789) cannot be honoured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NextExpectedProblem {
    /// 789 occurs more than once: no occurrence can be trusted over the
    /// others (`SessionRejectReason` 13).
    Repeated,
    /// 789 is not a sequence number: empty, carrying anything but the digits
    /// `0` to `9`, or above `u64::MAX`.
    Malformed {
        /// The value, truncated to [`MAX_ECHOED_VALUE`] bytes and escaped.
        value: String,
    },
    /// 789 is 0, which names no message: FIX numbers messages from 1.
    Zero,
    /// 789 is above the next `MsgSeqNum` this session sends: the counterparty
    /// claims to have received messages that were never sent. Unrecoverable
    /// in this Logon exchange.
    AheadOfSent {
        /// The value the counterparty declared.
        declared: u64,
        /// The next `MsgSeqNum` this session sends.
        next_outbound: u64,
    },
}

impl NextExpectedProblem {
    /// The session-level Reject an initiator sends, before its Logout, for a
    /// malformed 789 on the Logon acknowledgement, `RefTagID` (371) 789; or
    /// `None` for [`NextExpectedProblem::AheadOfSent`], which is answered by a
    /// Logout alone.
    ///
    /// The codes follow the ones the acknowledgement's `HeartBtInt` (108)
    /// gets: 13 for a repeated tag, 6 ("incorrect data format for value")
    /// for a value that is not a number, 5 ("value is incorrect") for 0. The
    /// acceptor answers every problem with a Logout alone: the Logon it would
    /// reject was never acknowledged.
    #[must_use]
    pub(crate) fn reject_reason(&self) -> Option<RejectReason> {
        let code = match self {
            Self::Repeated => 13,
            Self::Malformed { .. } => 6,
            Self::Zero => 5,
            Self::AheadOfSent { .. } => return None,
        };
        Some(RejectReason::new(code, self.to_string()).with_ref_tag(NEXT_EXPECTED_MSG_SEQ_NUM))
    }
}

impl std::fmt::Display for NextExpectedProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Repeated => f.write_str("NextExpectedMsgSeqNum (789) appears more than once"),
            Self::Malformed { value } => write!(
                f,
                "NextExpectedMsgSeqNum (789) '{value}' is not a sequence number"
            ),
            Self::Zero => f.write_str(
                "NextExpectedMsgSeqNum (789) is 0, which names no message; sequence numbers \
                 start at 1",
            ),
            Self::AheadOfSent {
                declared,
                next_outbound,
            } => write!(
                f,
                "NextExpectedMsgSeqNum (789) {declared} is higher than expected: the next \
                 MsgSeqNum this session sends is {next_outbound}, so the counterparty expects \
                 messages that were never sent"
            ),
        }
    }
}

/// What a counterparty's `NextExpectedMsgSeqNum` (789) asks of this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NextExpectedPlan {
    /// The counterparty has every message this session sent before its own
    /// Logon or acknowledgement: nothing to resend.
    InStep,
    /// The counterparty missed the messages numbered `begin..end`: resend
    /// them once the session is Active, as if a `ResendRequest` (2) had asked
    /// for exactly that range.
    Replay {
        /// The first number to resend: the counterparty's 789.
        begin: u64,
        /// The first number **not** resent: the `MsgSeqNum` of this session's
        /// own Logon or acknowledgement.
        end: u64,
    },
}

impl NextExpectedPlan {
    /// The range to resend once Active, as `(first, exclusive end)`, or
    /// `None` when there is nothing to resend.
    #[must_use]
    pub(crate) const fn replay_range(self) -> Option<(u64, u64)> {
        match self {
            Self::InStep => None,
            Self::Replay { begin, end } => Some((begin, end)),
        }
    }
}

/// Reads the `NextExpectedMsgSeqNum` (789) a counterparty declared on its
/// Logon or Logon acknowledgement.
///
/// 789 is a body field of the Logon, so it is read across the whole message
/// and must occur once ([`wire::message_field`]). Absent is `Ok(None)`: the
/// counterparty does not use 789, and the Logon exchange goes on as without
/// it.
///
/// # Errors
/// [`NextExpectedProblem::Repeated`] when 789 occurs more than once, and
/// whatever [`parse_value`] refuses.
pub(crate) fn read_next_expected(
    raw: &RawMessage<'_>,
) -> Result<Option<NonZeroU64>, NextExpectedProblem> {
    match wire::message_field(raw, NEXT_EXPECTED_MSG_SEQ_NUM) {
        FieldOccurrence::Absent => Ok(None),
        FieldOccurrence::Repeated => Err(NextExpectedProblem::Repeated),
        FieldOccurrence::Once(value) => parse_value(value).map(Some),
    }
}

/// Parses a 789 value: one or more ASCII digits (leading zeros allowed, as
/// for any FIX `int`), naming a positive `u64`.
///
/// No sign is accepted: a sequence number is never negative, and FIX's `int`
/// allows no `+`. The value is checked byte by byte before it is read as
/// text, so nothing that is not a digit is ever interpreted.
///
/// # Errors
/// [`NextExpectedProblem::Malformed`] for anything else, including a value
/// above `u64::MAX`, and [`NextExpectedProblem::Zero`] for 0.
pub(crate) fn parse_value(value: &[u8]) -> Result<NonZeroU64, NextExpectedProblem> {
    let malformed = || {
        let shown = value.get(..MAX_ECHOED_VALUE).unwrap_or(value);
        NextExpectedProblem::Malformed {
            value: shown.escape_ascii().to_string(),
        }
    };
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(malformed());
    }
    let parsed = std::str::from_utf8(value)
        .ok()
        .and_then(|text| text.parse::<u64>().ok())
        .ok_or_else(malformed)?;
    NonZeroU64::new(parsed).ok_or(NextExpectedProblem::Zero)
}

/// Decides what a counterparty's `NextExpectedMsgSeqNum` (789) asks of this
/// session.
///
/// `own_logon_seq` is the `MsgSeqNum` of this session's own Logon (an
/// initiator) or acknowledgement (an acceptor), and `next_outbound` the next
/// `MsgSeqNum` this session sends at the moment the 789 is read: for an
/// acceptor, which reads the initiator's 789 before acknowledging, both are
/// the number its acknowledgement takes; for an initiator, which reads the
/// acceptor's 789 on the acknowledgement, `next_outbound` is one past its
/// Logon. Both are taken after any sequence reset the Logon exchange makes,
/// where a reset session's own Logon or acknowledgement is 1.
///
/// - `declared > next_outbound`: [`NextExpectedProblem::AheadOfSent`].
/// - `declared < own_logon_seq`: [`NextExpectedPlan::Replay`] of
///   `declared..own_logon_seq`, which stops before this session's own Logon
///   (see the module documentation).
/// - otherwise [`NextExpectedPlan::InStep`].
///
/// # Errors
/// [`NextExpectedProblem::AheadOfSent`] as above.
pub(crate) const fn plan(
    declared: NonZeroU64,
    own_logon_seq: u64,
    next_outbound: u64,
) -> Result<NextExpectedPlan, NextExpectedProblem> {
    let declared = declared.get();
    if declared > next_outbound {
        return Err(NextExpectedProblem::AheadOfSent {
            declared,
            next_outbound,
        });
    }
    if declared < own_logon_seq {
        return Ok(NextExpectedPlan::Replay {
            begin: declared,
            end: own_logon_seq,
        });
    }
    Ok(NextExpectedPlan::InStep)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A positive sequence number for the tests.
    #[track_caller]
    fn seq(value: u64) -> NonZeroU64 {
        match NonZeroU64::new(value) {
            Some(value) => value,
            None => panic!("test sequence numbers are positive"),
        }
    }

    /// A FIX.4.4 Logon frame with the given body fields, built by hand so a
    /// test can repeat a tag or carry any bytes.
    fn logon_with(body_fields: &[(u32, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (tag, value) in [
            (35, &b"A"[..]),
            (49, b"VENUE"),
            (56, b"CLIENT"),
            (34, b"1"),
            (52, b"20261018-12:00:00.000"),
            (98, b"0"),
            (108, b"30"),
        ]
        .into_iter()
        .chain(body_fields.iter().copied())
        {
            body.extend_from_slice(format!("{tag}=").as_bytes());
            body.extend_from_slice(value);
            body.push(0x01);
        }
        let mut frame = Vec::new();
        frame.extend_from_slice(b"8=FIX.4.4\x01");
        frame.extend_from_slice(format!("9={}\x01", body.len()).as_bytes());
        frame.extend_from_slice(&body);
        let sum: u64 = frame.iter().map(|&byte| u64::from(byte)).sum();
        frame.extend_from_slice(format!("10={:03}\x01", sum % 256).as_bytes());
        frame
    }

    /// Reads 789 off a hand-built Logon.
    fn read(body_fields: &[(u32, &[u8])]) -> Result<Option<NonZeroU64>, NextExpectedProblem> {
        let frame = logon_with(body_fields);
        match wire::decode_frame(&frame) {
            Ok(raw) => read_next_expected(&raw),
            Err(err) => panic!("test Logon must decode: {err}"),
        }
    }

    #[test]
    fn test_read_next_expected_absent_is_none() {
        assert_eq!(read(&[]), Ok(None));
    }

    #[test]
    fn test_read_next_expected_reads_the_body_field() {
        assert_eq!(read(&[(141, b"Y"), (789, b"7")]), Ok(Some(seq(7))));
    }

    #[test]
    fn test_read_next_expected_repeated_is_refused() {
        assert_eq!(
            read(&[(789, b"7"), (789, b"7")]),
            Err(NextExpectedProblem::Repeated)
        );
    }

    #[test]
    fn test_read_next_expected_zero_and_non_numeric_are_refused() {
        assert_eq!(read(&[(789, b"0")]), Err(NextExpectedProblem::Zero));
        assert_eq!(
            read(&[(789, b"abc")]),
            Err(NextExpectedProblem::Malformed {
                value: "abc".to_string()
            })
        );
    }

    #[test]
    fn test_parse_value_accepts_digits_and_leading_zeros() {
        assert_eq!(parse_value(b"1"), Ok(seq(1)));
        assert_eq!(parse_value(b"007"), Ok(seq(7)));
        assert_eq!(parse_value(b"18446744073709551615"), Ok(seq(u64::MAX)));
    }

    #[test]
    fn test_parse_value_refuses_zero() {
        assert_eq!(parse_value(b"0"), Err(NextExpectedProblem::Zero));
        assert_eq!(parse_value(b"000"), Err(NextExpectedProblem::Zero));
    }

    #[test]
    fn test_parse_value_refuses_anything_but_digits() {
        for value in [
            &b""[..],
            b"+5",
            b"-1",
            b" 5",
            b"5 ",
            b"1.0",
            b"0x10",
            b"\xff\xfe",
        ] {
            assert!(
                matches!(
                    parse_value(value),
                    Err(NextExpectedProblem::Malformed { .. })
                ),
                "{value:?} must be refused as malformed"
            );
        }
    }

    #[test]
    fn test_parse_value_refuses_a_value_above_u64_max() {
        assert!(matches!(
            parse_value(b"18446744073709551616"),
            Err(NextExpectedProblem::Malformed { .. })
        ));
    }

    #[test]
    fn test_parse_value_echo_is_bounded_and_escaped() {
        let long = [b'9'; 64];
        let mut with_letter = long.to_vec();
        with_letter.push(b'x');
        match parse_value(&with_letter) {
            Err(NextExpectedProblem::Malformed { value }) => {
                assert_eq!(value.len(), MAX_ECHOED_VALUE);
            }
            other => panic!("expected a malformed value, got {other:?}"),
        }
        match parse_value(b"\x01\xff") {
            Err(NextExpectedProblem::Malformed { value }) => assert_eq!(value, "\\x01\\xff"),
            other => panic!("expected a malformed value, got {other:?}"),
        }
    }

    #[test]
    fn test_plan_acceptor_in_step_when_the_peer_expects_the_ack() {
        // The acceptor's ack will be 5; the initiator expects 5.
        assert_eq!(plan(seq(5), 5, 5), Ok(NextExpectedPlan::InStep));
    }

    #[test]
    fn test_plan_acceptor_replays_below_its_ack() {
        assert_eq!(
            plan(seq(3), 5, 5),
            Ok(NextExpectedPlan::Replay { begin: 3, end: 5 })
        );
        assert_eq!(
            plan(seq(1), 5, 5),
            Ok(NextExpectedPlan::Replay { begin: 1, end: 5 })
        );
    }

    #[test]
    fn test_plan_acceptor_refuses_a_peer_ahead_of_what_was_sent() {
        assert_eq!(
            plan(seq(6), 5, 5),
            Err(NextExpectedProblem::AheadOfSent {
                declared: 6,
                next_outbound: 5
            })
        );
    }

    #[test]
    fn test_plan_initiator_bounds() {
        // The initiator's Logon was 5, so it sends 6 next.
        assert_eq!(plan(seq(6), 5, 6), Ok(NextExpectedPlan::InStep));
        // The acceptor did not count the Logon: the range below it is empty.
        assert_eq!(plan(seq(5), 5, 6), Ok(NextExpectedPlan::InStep));
        assert_eq!(
            plan(seq(2), 5, 6),
            Ok(NextExpectedPlan::Replay { begin: 2, end: 5 })
        );
        assert_eq!(
            plan(seq(7), 5, 6),
            Err(NextExpectedProblem::AheadOfSent {
                declared: 7,
                next_outbound: 6
            })
        );
    }

    #[test]
    fn test_plan_after_a_reset_never_replays() {
        // Acceptor after a reset: its ack is 1, and the initiator's 141=Y
        // Logon declares 789=1.
        assert_eq!(plan(seq(1), 1, 1), Ok(NextExpectedPlan::InStep));
        assert!(matches!(
            plan(seq(2), 1, 1),
            Err(NextExpectedProblem::AheadOfSent { .. })
        ));
        // Initiator after a reset: its Logon was 1, the ack declares 2.
        assert_eq!(plan(seq(2), 1, 2), Ok(NextExpectedPlan::InStep));
        assert_eq!(plan(seq(1), 1, 2), Ok(NextExpectedPlan::InStep));
        assert!(matches!(
            plan(seq(3), 1, 2),
            Err(NextExpectedProblem::AheadOfSent { .. })
        ));
    }

    #[test]
    fn test_plan_at_the_top_of_the_sequence_space() {
        assert_eq!(
            plan(seq(u64::MAX), u64::MAX, u64::MAX),
            Ok(NextExpectedPlan::InStep)
        );
        assert_eq!(
            plan(seq(1), u64::MAX, u64::MAX),
            Ok(NextExpectedPlan::Replay {
                begin: 1,
                end: u64::MAX
            })
        );
    }

    #[test]
    fn test_replay_range_of_each_plan() {
        assert_eq!(NextExpectedPlan::InStep.replay_range(), None);
        assert_eq!(
            NextExpectedPlan::Replay { begin: 2, end: 9 }.replay_range(),
            Some((2, 9))
        );
    }

    #[test]
    fn test_reject_reason_codes() {
        let code =
            |problem: NextExpectedProblem| problem.reject_reason().map(|r| (r.code, r.ref_tag));
        assert_eq!(code(NextExpectedProblem::Repeated), Some((13, Some(789))));
        assert_eq!(
            code(NextExpectedProblem::Malformed {
                value: "x".to_string()
            }),
            Some((6, Some(789)))
        );
        assert_eq!(code(NextExpectedProblem::Zero), Some((5, Some(789))));
        assert_eq!(
            code(NextExpectedProblem::AheadOfSent {
                declared: 9,
                next_outbound: 4
            }),
            None,
            "a value above what was sent is answered by a Logout alone"
        );
    }

    #[test]
    fn test_problem_texts_name_the_tag() {
        for problem in [
            NextExpectedProblem::Repeated,
            NextExpectedProblem::Malformed {
                value: "x".to_string(),
            },
            NextExpectedProblem::Zero,
            NextExpectedProblem::AheadOfSent {
                declared: 9,
                next_outbound: 4,
            },
        ] {
            let text = problem.to_string();
            assert!(text.contains("NextExpectedMsgSeqNum (789)"), "{text}");
        }
        let ahead = NextExpectedProblem::AheadOfSent {
            declared: 9,
            next_outbound: 4,
        }
        .to_string();
        assert!(
            ahead.contains("higher than expected") && ahead.contains('9') && ahead.contains('4')
        );
    }
}
