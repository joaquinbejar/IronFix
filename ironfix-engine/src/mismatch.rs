/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! The report of a Logon exchange whose sequence numbers do not match the
//! state the session started from (issue #80, ADR-0015).
//!
//! A session resumed on a standby process, or from a store that lags the one
//! the previous process wrote, starts from counters the counterparty may not
//! agree with. The engine compares them once per Logon exchange, in both
//! roles, and reports a disagreement through
//! [`Application::on_sequence_mismatch`](crate::Application::on_sequence_mismatch)
//! as one [`SequenceMismatch`].
//!
//! # What is compared
//!
//! The baseline is the **effective startup counters**: the next sender and
//! next target numbers the session actually starts from, after the engine
//! has chosen between counters recovered from an attached store (after
//! `refresh()`), explicit seeds from `with_initial_sequences`, and a reset.
//! What the store held is reported beside them
//! ([`SequenceMismatch::stored_next_sender`],
//! [`SequenceMismatch::stored_next_target`]) and never compared.
//!
//! - **Inbound** ([`InboundMismatch`]): the `MsgSeqNum` (34) of the
//!   counterparty's Logon (initiator: its acknowledgement) against the
//!   effective next target.
//! - **Outbound** ([`OutboundMismatch`]): the counterparty's
//!   `NextExpectedMsgSeqNum` (789), when this session uses 789 and the
//!   counterparty declared a well-formed value, against the number of this
//!   side's own Logon (or acknowledgement) and its next outbound number, as
//!   ADR-0021 reads them. The `MsgSeqNum` of the counterparty's Logon is
//!   never read as a statement about our numbers.
//!
//! A report is made only when at least one comparison differs, and never for
//! an exchange that carries `ResetSeqNumFlag` (141) = Y, in either direction:
//! a reset discards both histories by agreement.
//!
//! # What it does not do
//!
//! The report never moves a counter (ADR-0021) and changes nothing the
//! engine does next: a gap is still recovered through 789 or a
//! `ResendRequest`, a Logon too low still closes the session, a 789 below our
//! Logon still queues a resend, and a 789 above our next outbound is still
//! refused with
//! [`EngineError::NextExpectedMsgSeqNum`](crate::EngineError::NextExpectedMsgSeqNum).
//! The report is made before any of that, so a session the existing rules
//! close is reported first. It carries numbers only: no frame, no `Text`,
//! nothing that could carry a credential.

use std::fmt;

/// How the counterparty's Logon `MsgSeqNum` (34) differs from the effective
/// next target number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum InboundMismatch {
    /// The Logon is numbered above the next number expected: the
    /// counterparty sent `first..=last` that this side has no record of
    /// receiving.
    Gap {
        /// The first missing `MsgSeqNum`: the effective next target.
        first: u64,
        /// The last missing `MsgSeqNum`: the Logon's number minus one.
        last: u64,
    },
    /// The Logon is numbered below the next number expected: the
    /// counterparty is behind this side's record of its stream.
    TooLow {
        /// The `MsgSeqNum` the Logon carried.
        received: u64,
        /// The effective next target number.
        expected: u64,
    },
}

impl fmt::Display for InboundMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gap { first, last } => write!(f, "inbound gap {first}..={last}"),
            Self::TooLow { received, expected } => {
                write!(
                    f,
                    "inbound Logon too low: received {received}, expected {expected}"
                )
            }
        }
    }
}

/// How the counterparty's `NextExpectedMsgSeqNum` (789) relates to this
/// side's outbound stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum OutboundMismatch {
    /// The counterparty declared no usable 789 (absent, malformed, or this
    /// session does not use 789): its Logon says nothing about our outbound
    /// stream. Not a mismatch on its own.
    NotDeclared,
    /// The counterparty's 789 agrees with our outbound stream: it lies
    /// between our own Logon number and our next outbound number. Not a
    /// mismatch on its own.
    Consistent {
        /// The 789 the counterparty declared.
        declared: u64,
    },
    /// The counterparty missed `first..=last`: its 789 is below the number of
    /// our own Logon (or acknowledgement). The engine resends that range
    /// once Active, as before.
    PeerMissed {
        /// The first missed `MsgSeqNum`: the declared 789.
        first: u64,
        /// The last missed `MsgSeqNum`: our own Logon's number minus one.
        last: u64,
    },
    /// The counterparty expects a number above our next outbound: it holds
    /// numbers our state has no record of sending, the signature of a
    /// lagging replica. The engine refuses the session, as before.
    PeerAhead {
        /// The 789 the counterparty declared.
        declared: u64,
        /// Our next outbound `MsgSeqNum`.
        next_outbound: u64,
    },
}

impl OutboundMismatch {
    /// Whether this is a disagreement ([`OutboundMismatch::PeerMissed`] or
    /// [`OutboundMismatch::PeerAhead`]).
    #[must_use]
    pub const fn is_mismatch(&self) -> bool {
        matches!(self, Self::PeerMissed { .. } | Self::PeerAhead { .. })
    }

    /// Compares a declared 789 with our own Logon number and next outbound
    /// number, with the boundaries ADR-0021's plan uses.
    #[must_use]
    fn compare(declared: Option<u64>, own_logon_seq: u64, next_outbound: u64) -> Self {
        let Some(declared) = declared else {
            return Self::NotDeclared;
        };
        if declared > next_outbound {
            return Self::PeerAhead {
                declared,
                next_outbound,
            };
        }
        if declared < own_logon_seq {
            // declared < own_logon_seq, so own_logon_seq >= 1 and the
            // subtraction cannot underflow.
            return match own_logon_seq.checked_sub(1) {
                Some(last) => Self::PeerMissed {
                    first: declared,
                    last,
                },
                None => {
                    debug_assert!(false, "own Logon number below a declared 789 is >= 1");
                    Self::Consistent { declared }
                }
            };
        }
        Self::Consistent { declared }
    }
}

impl fmt::Display for OutboundMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotDeclared => f.write_str("outbound not declared"),
            Self::Consistent { declared } => write!(f, "outbound consistent (789={declared})"),
            Self::PeerMissed { first, last } => {
                write!(f, "counterparty missed outbound {first}..={last}")
            }
            Self::PeerAhead {
                declared,
                next_outbound,
            } => write!(
                f,
                "counterparty expects {declared}, above the next outbound {next_outbound}"
            ),
        }
    }
}

/// A Logon exchange whose numbers do not match the state the session
/// started from.
///
/// See the [module documentation](self) for what is compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SequenceMismatch {
    /// The next sender number the session started from.
    effective_next_sender: u64,
    /// The next target number the session started from.
    effective_next_target: u64,
    /// The store's next sender number before any seed or reset.
    stored_next_sender: Option<u64>,
    /// The store's next target number before any seed or reset.
    stored_next_target: Option<u64>,
    /// The `MsgSeqNum` (34) of the counterparty's Logon.
    peer_logon_seq: u64,
    /// The counterparty's 789, when declared and used.
    peer_next_expected: Option<u64>,
    /// The inbound comparison.
    inbound: Option<InboundMismatch>,
    /// The outbound comparison.
    outbound: OutboundMismatch,
}

impl SequenceMismatch {
    /// Compares a Logon exchange with the effective startup counters, and
    /// returns the report when at least one comparison differs.
    ///
    /// `effective_next_sender` is also the number of our own Logon (or
    /// acknowledgement); `next_outbound` is the next number we send after it,
    /// as ADR-0021 reads it in each role.
    #[must_use]
    pub(crate) fn compare(
        effective: (u64, u64),
        stored: Option<(u64, u64)>,
        peer_logon_seq: u64,
        peer_next_expected: Option<u64>,
        next_outbound: u64,
    ) -> Option<Self> {
        let (effective_next_sender, effective_next_target) = effective;
        let inbound = match peer_logon_seq.cmp(&effective_next_target) {
            std::cmp::Ordering::Equal => None,
            std::cmp::Ordering::Less => Some(InboundMismatch::TooLow {
                received: peer_logon_seq,
                expected: effective_next_target,
            }),
            // peer_logon_seq > effective_next_target >= 0, so it is >= 1.
            std::cmp::Ordering::Greater => match peer_logon_seq.checked_sub(1) {
                Some(last) => Some(InboundMismatch::Gap {
                    first: effective_next_target,
                    last,
                }),
                None => {
                    debug_assert!(false, "a Logon number above the target is >= 1");
                    None
                }
            },
        };
        let outbound =
            OutboundMismatch::compare(peer_next_expected, effective_next_sender, next_outbound);
        (inbound.is_some() || outbound.is_mismatch()).then_some(Self {
            effective_next_sender,
            effective_next_target,
            stored_next_sender: stored.map(|(sender, _)| sender),
            stored_next_target: stored.map(|(_, target)| target),
            peer_logon_seq,
            peer_next_expected,
            inbound,
            outbound,
        })
    }

    /// The next sender `MsgSeqNum` the session started from: the number of
    /// its own Logon (or acknowledgement).
    #[must_use]
    pub const fn effective_next_sender(&self) -> u64 {
        self.effective_next_sender
    }

    /// The next target `MsgSeqNum` the session started from: the number it
    /// expected the counterparty's Logon to carry.
    #[must_use]
    pub const fn effective_next_target(&self) -> u64 {
        self.effective_next_target
    }

    /// The next sender number the attached store held before any seed was
    /// applied, or `None` without a store. Reported, never compared.
    #[must_use]
    pub const fn stored_next_sender(&self) -> Option<u64> {
        self.stored_next_sender
    }

    /// The next target number the attached store held before any seed was
    /// applied, or `None` without a store. Reported, never compared.
    #[must_use]
    pub const fn stored_next_target(&self) -> Option<u64> {
        self.stored_next_target
    }

    /// The `MsgSeqNum` (34) of the counterparty's Logon (initiator: its
    /// acknowledgement).
    #[must_use]
    pub const fn peer_logon_seq(&self) -> u64 {
        self.peer_logon_seq
    }

    /// The counterparty's `NextExpectedMsgSeqNum` (789), when this session
    /// uses 789 and the counterparty declared a well-formed value.
    #[must_use]
    pub const fn peer_next_expected(&self) -> Option<u64> {
        self.peer_next_expected
    }

    /// The inbound comparison, or `None` when the Logon carried the expected
    /// number.
    #[must_use]
    pub const fn inbound(&self) -> Option<InboundMismatch> {
        self.inbound
    }

    /// The outbound comparison.
    #[must_use]
    pub const fn outbound(&self) -> OutboundMismatch {
        self.outbound
    }
}

impl fmt::Display for SequenceMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Logon sequence mismatch: started at sender {} / target {}, peer Logon {}",
            self.effective_next_sender, self.effective_next_target, self.peer_logon_seq
        )?;
        if let Some(inbound) = self.inbound {
            write!(f, "; {inbound}")?;
        }
        write!(f, "; {}", self.outbound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_report_when_everything_matches() {
        assert_eq!(SequenceMismatch::compare((5, 9), None, 9, None, 6), None);
        assert_eq!(SequenceMismatch::compare((5, 9), None, 9, Some(5), 6), None);
        assert_eq!(SequenceMismatch::compare((5, 9), None, 9, Some(6), 6), None);
        // Acceptor shape: the ack is the next outbound.
        assert_eq!(SequenceMismatch::compare((5, 9), None, 9, Some(5), 5), None);
    }

    #[test]
    fn test_inbound_gap_and_too_low() {
        let gap = SequenceMismatch::compare((1, 4), None, 9, None, 2);
        assert_eq!(
            gap.and_then(|m| m.inbound()),
            Some(InboundMismatch::Gap { first: 4, last: 8 })
        );
        assert_eq!(
            gap.map(|m| m.outbound()),
            Some(OutboundMismatch::NotDeclared)
        );
        let low = SequenceMismatch::compare((1, 4), Some((3, 2)), 2, None, 2);
        assert_eq!(
            low.and_then(|m| m.inbound()),
            Some(InboundMismatch::TooLow {
                received: 2,
                expected: 4
            })
        );
        assert_eq!(low.and_then(|m| m.stored_next_target()), Some(2));
        assert_eq!(low.and_then(|m| m.stored_next_sender()), Some(3));
    }

    #[test]
    fn test_outbound_peer_missed_and_ahead() {
        let missed = SequenceMismatch::compare((7, 3), None, 3, Some(4), 8);
        assert_eq!(
            missed.map(|m| m.outbound()),
            Some(OutboundMismatch::PeerMissed { first: 4, last: 6 })
        );
        assert_eq!(missed.and_then(|m| m.inbound()), None);
        let ahead = SequenceMismatch::compare((7, 3), None, 3, Some(12), 8);
        assert_eq!(
            ahead.map(|m| m.outbound()),
            Some(OutboundMismatch::PeerAhead {
                declared: 12,
                next_outbound: 8
            })
        );
    }

    #[test]
    fn test_seeds_over_store_compare_the_effective_counters() {
        // Store 10/20, seeds 15/30, peer Logon 30: in sync.
        assert_eq!(
            SequenceMismatch::compare((15, 30), Some((10, 20)), 30, None, 16),
            None
        );
    }

    #[test]
    fn test_boundaries_do_not_underflow() {
        assert_eq!(
            SequenceMismatch::compare((1, 0), None, u64::MAX, None, 2).and_then(|m| m.inbound()),
            Some(InboundMismatch::Gap {
                first: 0,
                last: u64::MAX - 1
            })
        );
        assert_eq!(
            OutboundMismatch::compare(Some(1), 1, 1),
            OutboundMismatch::Consistent { declared: 1 }
        );
    }

    #[test]
    fn test_display_carries_numbers_only() {
        let report = SequenceMismatch::compare((7, 3), None, 5, Some(12), 8);
        assert_eq!(
            report.map(|m| m.to_string()).as_deref(),
            Some(
                "Logon sequence mismatch: started at sender 7 / target 3, peer Logon 5; \
                 inbound gap 3..=4; counterparty expects 12, above the next outbound 8"
            )
        );
    }
}
