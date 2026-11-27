/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/11/26
******************************************************************************/

//! Sans-IO core: the capture points of a session (issue #223).
//!
//! An audit or replay capture needs to know where each frame stands relative
//! to the session's sequence handling: read and framed, accepted into the
//! sequence, held above a gap, refused; queued for the wire, written, or
//! resent. Those points are protocol decisions, so they live here, and every
//! driver reports them the same way.
//!
//! - [`CapturePoint`] names one point: an inbound frame framed, the core's
//!   [`InboundVerdict`] on it, an outbound frame queued (a resend replay or
//!   gap fill is [`FrameKind::Replay`] or [`FrameKind::GapFill`]), and the
//!   write result of an outbound frame ([`WriteClass`]).
//! - The verdict comes from the core's own routing decisions:
//!   [`inbound_verdict`] for an [`InboundRoute`],
//!   [`sequence_reset_screen_verdict`] for a [`ResetScreen`], and
//!   [`sequence_reset_verdict`] for a [`ResetDecision`]. A driver does not
//!   reinterpret the route to decide what to report.
//! - [`FrameCapture`] is the synchronous sink a driver hands the points to,
//!   with the frame bytes when there are any and the driver's own clock
//!   reading (the core reads no clock, ADR-0002).
//!
//! `ironfix-engine` is the first driver: its `FrameObserver` is fed from
//! these points, and its `Direction` and `FrameKind` are the types defined
//! here.
//!
//! # Credentials
//!
//! A captured frame is raw bytes. A Logon can carry `Password` (554),
//! `NewPassword` (925) and `RawData` (96); redacting what a sink stores or
//! logs is the sink's responsibility.

use std::time::Instant;

use crate::sans_io::{GapDisposition, InboundRoute, InboundSequence, ResetDecision, ResetScreen};

/// Which way a frame travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum Direction {
    /// Read from the counterparty.
    Inbound,
    /// Written to the counterparty.
    Outbound,
}

/// What kind of frame a capture point is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum FrameKind {
    /// A frame of the Logon handshake, before the session is Active: the
    /// Logons themselves, frames read while waiting for one, and the Rejects
    /// and Logouts that refuse one.
    Handshake,
    /// A frame of the established session that is not a replay: application
    /// and administrative messages under a new `MsgSeqNum` (34), and every
    /// inbound frame once the session is Active.
    Session,
    /// A stored message resent, with `PossDupFlag` (43) = Y, under the
    /// number it was first sent with: the answer to a `ResendRequest` (2) or
    /// the resend a `NextExpectedMsgSeqNum` (789) asked for.
    Replay,
    /// A `SequenceReset`-GapFill (4, 123 = Y) written in a resend, under the
    /// first number it fills.
    GapFill,
}

impl FrameKind {
    /// Whether the frame re-occupies a number already spent: a
    /// [`FrameKind::Replay`] or a [`FrameKind::GapFill`].
    #[must_use]
    pub const fn is_replay(self) -> bool {
        matches!(self, Self::Replay | Self::GapFill)
    }
}

/// Why the core refused an inbound frame's `MsgSeqNum` (34) or the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboundRefusal {
    /// Below the expectation with `PossDupFlag` (43) = Y: a duplicate,
    /// ignored as FIX requires.
    Duplicate,
    /// Below the expectation without `PossDupFlag` (43) = Y: the streams have
    /// diverged and the session ends.
    TooLow {
        /// The number the session expected.
        expected: u64,
    },
    /// The inbound counter is at `u64::MAX`: the session ends.
    Exhausted,
    /// A `SequenceReset` (4) the core refused: a malformed `GapFillFlag`
    /// (123), a missing or unusable `NewSeqNo` (36), a GapFill that does not
    /// advance, or a Reset below the expectation. The driver answers it with
    /// a session Reject (3).
    InvalidSequenceReset,
    /// The driver's application refused the message (in the engine,
    /// `from_admin` returned an error). Reported by the driver: the core
    /// cannot see the application's answer.
    Refused,
    /// Above the expectation, and a message with the same number is already
    /// queued above the gap: the copy is dropped.
    QueuedCopy,
    /// Above the expectation with a body that does not decode: not queued,
    /// and left to its resend.
    Malformed,
}

/// The core's verdict on an inbound frame, relative to sequence handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboundVerdict {
    /// The number is the one expected and the driver acts on the message.
    /// It may still answer it with a session Reject (3) for its content; the
    /// number is consumed either way.
    Accepted {
        /// The frame's `MsgSeqNum` (34).
        seq: u64,
    },
    /// Above the expectation, and acted on now without consuming its number:
    /// an administrative message inside a gap (a Logout among them).
    AcceptedAhead {
        /// The frame's `MsgSeqNum` (34).
        seq: u64,
        /// The number the session expected: the start of the gap.
        expected: u64,
    },
    /// Above the expectation and not acted on now: the gap is requested, and
    /// the frame may be queued to be released in turn.
    Deferred {
        /// The frame's `MsgSeqNum` (34).
        seq: u64,
        /// The number the session expected: the start of the gap.
        expected: u64,
    },
    /// Not acted on.
    Rejected {
        /// The frame's `MsgSeqNum` (34).
        seq: u64,
        /// Why.
        reason: InboundRefusal,
    },
}

impl InboundVerdict {
    /// The frame's `MsgSeqNum` (34).
    #[must_use]
    pub const fn seq(&self) -> u64 {
        match *self {
            Self::Accepted { seq }
            | Self::AcceptedAhead { seq, .. }
            | Self::Deferred { seq, .. }
            | Self::Rejected { seq, .. } => seq,
        }
    }

    /// Whether the driver acts on the message now.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. } | Self::AcceptedAhead { .. })
    }
}

/// The verdict on an in-sequence frame of number `seq`: accepted, unless
/// `seq` is `u64::MAX`, past which the next inbound number cannot be
/// counted and the session ends.
#[must_use]
pub const fn in_sequence_verdict(seq: u64) -> InboundVerdict {
    match seq.checked_add(1) {
        Some(_) => InboundVerdict::Accepted { seq },
        None => InboundVerdict::Rejected {
            seq,
            reason: InboundRefusal::Exhausted,
        },
    }
}

/// The verdict on an inbound frame of number `seq` the core routed as
/// `route` ([`route_inbound`](crate::sans_io::route_inbound)).
///
/// `None` for a `SequenceReset` (4): it has its own rules, and its verdict
/// comes from [`sequence_reset_screen_verdict`] and, once the application
/// has seen it, [`sequence_reset_verdict`]. `None` too for a frame above the
/// expectation: whether it is acted on, queued or dropped as a copy depends
/// on the gap queue, so its verdict comes from [`gap_verdict`].
#[must_use]
pub const fn inbound_verdict(route: &InboundRoute, seq: u64) -> Option<InboundVerdict> {
    let verdict = match *route {
        InboundRoute::SequenceReset | InboundRoute::Gap { .. } => return None,
        InboundRoute::Admin { .. } | InboundRoute::App => in_sequence_verdict(seq),
        InboundRoute::Duplicate => InboundVerdict::Rejected {
            seq,
            reason: InboundRefusal::Duplicate,
        },
        InboundRoute::TooLow { expected, .. } => InboundVerdict::Rejected {
            seq,
            reason: InboundRefusal::TooLow { expected },
        },
        InboundRoute::Exhausted => InboundVerdict::Rejected {
            seq,
            reason: InboundRefusal::Exhausted,
        },
    };
    Some(verdict)
}

/// The verdict on a frame of number `seq` above the expectation `expected`,
/// handled as `then` says, reported before the gap is requested.
///
/// `queued_copy` is whether the gap queue already holds a message under
/// this number ([`SessionCore::gap_copy_queued`](crate::SessionCore::gap_copy_queued)):
/// such a copy is dropped, unless it is a Logout, which is acted on and
/// empties the queue. Otherwise an application message is deferred to its
/// resend, and an administrative message is acted on ahead of the gap.
#[must_use]
pub const fn gap_verdict(
    then: GapDisposition,
    queued_copy: bool,
    seq: u64,
    expected: u64,
) -> InboundVerdict {
    match then {
        GapDisposition::Dispatch => InboundVerdict::AcceptedAhead { seq, expected },
        GapDisposition::QueueFrame | GapDisposition::KeepNumber if queued_copy => {
            InboundVerdict::Rejected {
                seq,
                reason: InboundRefusal::QueuedCopy,
            }
        }
        GapDisposition::QueueFrame => InboundVerdict::Deferred { seq, expected },
        GapDisposition::KeepNumber => InboundVerdict::AcceptedAhead { seq, expected },
    }
}

/// The verdict on a frame of number `seq` whose header is sound and whose
/// body does not decode, from its sequence classification
/// ([`classify_inbound`](crate::sans_io::classify_inbound)). In sequence its
/// number is consumed and the driver answers it with a session Reject (3),
/// so it is accepted into the sequence. Above the expectation it is never
/// queued (its body cannot be acted on): it is rejected as
/// [`InboundRefusal::Malformed`], and its resend gets its own verdict.
#[must_use]
pub const fn malformed_verdict(sequence: &InboundSequence, seq: u64) -> InboundVerdict {
    match *sequence {
        InboundSequence::InSequence => in_sequence_verdict(seq),
        InboundSequence::Duplicate { .. } => InboundVerdict::Rejected {
            seq,
            reason: InboundRefusal::Duplicate,
        },
        InboundSequence::TooLow { expected, .. } => InboundVerdict::Rejected {
            seq,
            reason: InboundRefusal::TooLow { expected },
        },
        InboundSequence::Gap { .. } => InboundVerdict::Rejected {
            seq,
            reason: InboundRefusal::Malformed,
        },
    }
}

/// The verdict on a frame of number `seq` queued above a gap and released
/// once the expectation reached it: it is now in sequence and acted on. It
/// follows the [`InboundVerdict::Deferred`] the frame got when it arrived,
/// without the frame being framed again.
#[must_use]
pub const fn released_verdict(seq: u64) -> InboundVerdict {
    in_sequence_verdict(seq)
}

/// The verdict on a `SequenceReset` (4) of number `seq` from its screen
/// ([`screen_sequence_reset`](crate::sans_io::screen_sequence_reset)).
/// `queued_copy` is whether the gap queue already holds a message under
/// this number: a gapped fill that is such a copy is dropped.
///
/// A Reset (which has no place in the sequence) reaches the application and
/// is reported accepted before the application runs; a refusal by the
/// application ([`InboundRefusal::Refused`]) or by the core
/// ([`sequence_reset_verdict`]) follows as a second verdict. An in-sequence
/// GapFill gets `None` here: its acceptance is reported with the decision
/// ([`sequence_reset_verdict`]), once the receive cursor has moved past it.
#[must_use]
pub const fn sequence_reset_screen_verdict(
    screen: &ResetScreen,
    queued_copy: bool,
    seq: u64,
) -> Option<InboundVerdict> {
    let verdict = match *screen {
        ResetScreen::GappedFill { .. } if queued_copy => InboundVerdict::Rejected {
            seq,
            reason: InboundRefusal::QueuedCopy,
        },
        ResetScreen::BadGapFillFlag => InboundVerdict::Rejected {
            seq,
            reason: InboundRefusal::InvalidSequenceReset,
        },
        ResetScreen::GappedFill { expected, .. } => InboundVerdict::Deferred { seq, expected },
        ResetScreen::DuplicateFill { .. } => InboundVerdict::Rejected {
            seq,
            reason: InboundRefusal::Duplicate,
        },
        ResetScreen::TooLowFill { expected, .. } => InboundVerdict::Rejected {
            seq,
            reason: InboundRefusal::TooLow { expected },
        },
        ResetScreen::Exhausted => InboundVerdict::Rejected {
            seq,
            reason: InboundRefusal::Exhausted,
        },
        ResetScreen::FillInSequence { .. } => return None,
        // Reset mode has no place in the sequence: its MsgSeqNum is not
        // counted, so it cannot exhaust the counter.
        ResetScreen::Reset => InboundVerdict::Accepted { seq },
    };
    Some(verdict)
}

/// The second verdict on a `SequenceReset` (4) of number `seq`, from the
/// core's decision on it
/// ([`decide_sequence_reset`](crate::sans_io::decide_sequence_reset)), made
/// once the application has accepted it: a rejection when the core refuses
/// it; for an applied GapFill (`gap_fill`), its acceptance, which the driver
/// reports once the receive cursor has moved; `None` for an applied Reset
/// (its screen verdict already said accepted).
#[must_use]
pub const fn sequence_reset_verdict(
    decision: &ResetDecision,
    gap_fill: bool,
    seq: u64,
) -> Option<InboundVerdict> {
    match decision {
        ResetDecision::Apply { .. } if gap_fill => Some(InboundVerdict::Accepted { seq }),
        ResetDecision::Apply { .. } => None,
        ResetDecision::MissingNewSeqNo
        | ResetDecision::FillNotAdvancing { .. }
        | ResetDecision::ResetBelowExpected { .. } => Some(InboundVerdict::Rejected {
            seq,
            reason: InboundRefusal::InvalidSequenceReset,
        }),
    }
}

/// How the write of an outbound frame ended, or that a message was never
/// written. The driver may keep a finer reason of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum WriteClass {
    /// A flush that covers the frame completed: the stream accepted every
    /// byte of it.
    Written,
    /// No byte of the message reached the stream. It was never queued.
    NotSent,
    /// A write was started and did not complete: the counterparty may have
    /// read all, part or none of the frame.
    Unknown,
}

/// One capture point of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapturePoint {
    /// An inbound frame passed framing, before the session acts on it.
    InboundFramed {
        /// What kind of frame it is.
        kind: FrameKind,
        /// Its `MsgSeqNum` (34), when the driver could read one.
        seq: Option<u64>,
        /// The driver's capture id for this frame, unique and increasing
        /// within the established session, so later points can name this
        /// exact frame. `None` for a handshake frame (it gets no verdict) or
        /// a driver that assigns no ids.
        frame_id: Option<u64>,
    },
    /// The core's verdict on an inbound frame of the established session.
    Inbound {
        /// The verdict.
        verdict: InboundVerdict,
        /// The capture id of the frame the verdict is about
        /// ([`CapturePoint::InboundFramed`]): for a frame released from the
        /// gap queue, the id of the frame that was queued. `None` when the
        /// driver assigns no ids.
        frame_id: Option<u64>,
    },
    /// An outbound frame was built and queued for the wire, before any byte
    /// of it goes to the stream. A resend is [`FrameKind::Replay`] or
    /// [`FrameKind::GapFill`].
    OutboundQueued {
        /// What kind of frame it is.
        kind: FrameKind,
        /// Its `MsgSeqNum` (34).
        seq: u64,
    },
    /// How the write of a queued frame ended, or that a message was never
    /// written ([`WriteClass::NotSent`], with no number when none was
    /// spent).
    OutboundResult {
        /// What kind of frame it is.
        kind: FrameKind,
        /// Its `MsgSeqNum` (34), when one was spent.
        seq: Option<u64>,
        /// How it ended.
        result: WriteClass,
    },
}

impl CapturePoint {
    /// A resend replay of the stored message numbered `seq`.
    #[must_use]
    pub const fn replayed(seq: u64) -> Self {
        Self::OutboundQueued {
            kind: FrameKind::Replay,
            seq,
        }
    }

    /// A `SequenceReset`-GapFill written in a resend, under the first number
    /// `seq` it fills.
    #[must_use]
    pub const fn gap_filled(seq: u64) -> Self {
        Self::OutboundQueued {
            kind: FrameKind::GapFill,
            seq,
        }
    }

    /// Which way the frame travels.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        match self {
            Self::InboundFramed { .. } | Self::Inbound { .. } => Direction::Inbound,
            Self::OutboundQueued { .. } | Self::OutboundResult { .. } => Direction::Outbound,
        }
    }

    /// What kind of frame the point is about. A verdict is always about a
    /// frame of the established session.
    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        match *self {
            Self::InboundFramed { kind, .. }
            | Self::OutboundQueued { kind, .. }
            | Self::OutboundResult { kind, .. } => kind,
            Self::Inbound { .. } => FrameKind::Session,
        }
    }

    /// The frame's `MsgSeqNum` (34), when known.
    #[must_use]
    pub const fn seq(&self) -> Option<u64> {
        match *self {
            Self::InboundFramed { seq, .. } | Self::OutboundResult { seq, .. } => seq,
            Self::Inbound { verdict, .. } => Some(verdict.seq()),
            Self::OutboundQueued { seq, .. } => Some(seq),
        }
    }

    /// The capture id of the inbound frame the point is about, when known.
    #[must_use]
    pub const fn frame_id(&self) -> Option<u64> {
        match *self {
            Self::InboundFramed { frame_id, .. } | Self::Inbound { frame_id, .. } => frame_id,
            Self::OutboundQueued { .. } | Self::OutboundResult { .. } => None,
        }
    }

    /// Whether the point is about a resend: a replay or a gap fill.
    #[must_use]
    pub const fn is_resend(&self) -> bool {
        self.kind().is_replay()
    }
}

/// The synchronous sink a driver reports capture points to.
///
/// Called inline on the driver's session task: it must be cheap, must not
/// block and must not panic. `frame` is the frame's bytes for
/// [`CapturePoint::InboundFramed`] and [`CapturePoint::OutboundQueued`], and
/// `None` for a verdict or a write result. `at` is the driver's clock
/// reading at the point.
pub trait FrameCapture {
    /// Reports one capture point.
    fn on_capture(&self, point: &CapturePoint, frame: Option<&[u8]>, at: Instant);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sans_io::{classify_inbound, route_inbound, screen_sequence_reset};
    use crate::sequence::SequenceManager;
    use ironfix_core::message::MsgType;
    use std::cell::RefCell;

    fn expecting(next: u64) -> SequenceManager {
        let sequences = SequenceManager::new();
        sequences.set_target_seq(next);
        sequences
    }

    #[test]
    fn test_frame_kind_is_replay() {
        assert!(FrameKind::Replay.is_replay());
        assert!(FrameKind::GapFill.is_replay());
        assert!(!FrameKind::Session.is_replay());
        assert!(!FrameKind::Handshake.is_replay());
    }

    #[test]
    fn test_in_sequence_messages_are_accepted() {
        let sequences = expecting(5);
        for msg_type in [MsgType::Heartbeat, MsgType::NewOrderSingle] {
            let route = route_inbound(&sequences, &msg_type, 5, || false);
            assert_eq!(
                inbound_verdict(&route, 5),
                Some(InboundVerdict::Accepted { seq: 5 })
            );
        }
    }

    #[test]
    fn test_low_numbers_are_rejected_with_their_reason() {
        let sequences = expecting(5);
        let route = route_inbound(&sequences, &MsgType::NewOrderSingle, 3, || false);
        assert_eq!(
            inbound_verdict(&route, 3),
            Some(InboundVerdict::Rejected {
                seq: 3,
                reason: InboundRefusal::TooLow { expected: 5 }
            })
        );
        let route = route_inbound(&sequences, &MsgType::NewOrderSingle, 3, || true);
        let verdict = inbound_verdict(&route, 3);
        assert!(matches!(
            verdict,
            Some(InboundVerdict::Rejected {
                seq: 3,
                reason: InboundRefusal::Duplicate
            })
        ));
        assert!(verdict.is_some_and(|v| !v.is_accepted()));
    }

    #[test]
    fn test_gapped_messages_wait_for_the_gap_verdict() {
        let sequences = expecting(5);
        for msg_type in [MsgType::NewOrderSingle, MsgType::Heartbeat, MsgType::Logout] {
            let route = route_inbound(&sequences, &msg_type, 9, || false);
            assert!(matches!(route, InboundRoute::Gap { .. }));
            assert_eq!(inbound_verdict(&route, 9), None);
        }
    }

    #[test]
    fn test_gap_verdict_defers_accepts_ahead_or_drops_a_copy() {
        assert_eq!(
            gap_verdict(GapDisposition::QueueFrame, false, 9, 5),
            InboundVerdict::Deferred {
                seq: 9,
                expected: 5
            }
        );
        let ahead = gap_verdict(GapDisposition::KeepNumber, false, 9, 5);
        assert_eq!(
            ahead,
            InboundVerdict::AcceptedAhead {
                seq: 9,
                expected: 5
            }
        );
        assert!(ahead.is_accepted());
        for then in [GapDisposition::QueueFrame, GapDisposition::KeepNumber] {
            assert_eq!(
                gap_verdict(then, true, 9, 5),
                InboundVerdict::Rejected {
                    seq: 9,
                    reason: InboundRefusal::QueuedCopy
                }
            );
        }
        // A Logout is acted on even over a queued number: it empties the
        // queue.
        for copy in [false, true] {
            assert_eq!(
                gap_verdict(GapDisposition::Dispatch, copy, 9, 5),
                InboundVerdict::AcceptedAhead {
                    seq: 9,
                    expected: 5
                }
            );
        }
    }

    #[test]
    fn test_in_sequence_at_the_last_number_is_exhausted() {
        let exhausted = InboundVerdict::Rejected {
            seq: u64::MAX,
            reason: InboundRefusal::Exhausted,
        };
        assert_eq!(in_sequence_verdict(u64::MAX), exhausted);
        assert_eq!(released_verdict(u64::MAX), exhausted);
        assert_eq!(
            inbound_verdict(&InboundRoute::App, u64::MAX),
            Some(exhausted)
        );
        assert_eq!(
            malformed_verdict(&InboundSequence::InSequence, u64::MAX),
            exhausted
        );
        assert_eq!(in_sequence_verdict(7), InboundVerdict::Accepted { seq: 7 });
    }

    #[test]
    fn test_malformed_verdict_follows_the_classification() {
        let sequences = expecting(5);
        let classify = |seq, poss_dup| classify_inbound(&sequences, seq, || poss_dup);
        assert_eq!(
            malformed_verdict(&classify(5, false), 5),
            InboundVerdict::Accepted { seq: 5 }
        );
        assert_eq!(
            malformed_verdict(&classify(3, true), 3),
            InboundVerdict::Rejected {
                seq: 3,
                reason: InboundRefusal::Duplicate
            }
        );
        assert_eq!(
            malformed_verdict(&classify(3, false), 3),
            InboundVerdict::Rejected {
                seq: 3,
                reason: InboundRefusal::TooLow { expected: 5 }
            }
        );
        assert_eq!(
            malformed_verdict(&classify(8, false), 8),
            InboundVerdict::Rejected {
                seq: 8,
                reason: InboundRefusal::Malformed
            }
        );
        assert_eq!(released_verdict(8), InboundVerdict::Accepted { seq: 8 });
    }

    #[test]
    fn test_exhausted_and_sequence_reset_routes() {
        assert_eq!(
            inbound_verdict(&InboundRoute::Exhausted, u64::MAX),
            Some(InboundVerdict::Rejected {
                seq: u64::MAX,
                reason: InboundRefusal::Exhausted
            })
        );
        assert_eq!(inbound_verdict(&InboundRoute::SequenceReset, 4), None);
    }

    #[test]
    fn test_sequence_reset_screen_verdicts() {
        let sequences = expecting(5);
        let gapped = screen_sequence_reset(&sequences, Some("Y"), 9, || false);
        assert_eq!(
            sequence_reset_screen_verdict(&gapped, false, 9),
            Some(InboundVerdict::Deferred {
                seq: 9,
                expected: 5
            })
        );
        assert_eq!(
            sequence_reset_screen_verdict(&gapped, true, 9),
            Some(InboundVerdict::Rejected {
                seq: 9,
                reason: InboundRefusal::QueuedCopy
            })
        );
        let bad = screen_sequence_reset(&sequences, Some("X"), 5, || false);
        assert_eq!(
            sequence_reset_screen_verdict(&bad, false, 5),
            Some(InboundVerdict::Rejected {
                seq: 5,
                reason: InboundRefusal::InvalidSequenceReset
            })
        );
        let duplicate = screen_sequence_reset(&sequences, Some("Y"), 3, || true);
        assert_eq!(
            sequence_reset_screen_verdict(&duplicate, false, 3),
            Some(InboundVerdict::Rejected {
                seq: 3,
                reason: InboundRefusal::Duplicate
            })
        );
        let too_low = screen_sequence_reset(&sequences, Some("Y"), 3, || false);
        assert_eq!(
            sequence_reset_screen_verdict(&too_low, false, 3),
            Some(InboundVerdict::Rejected {
                seq: 3,
                reason: InboundRefusal::TooLow { expected: 5 }
            })
        );
        let in_sequence = screen_sequence_reset(&sequences, Some("Y"), 5, || false);
        assert_eq!(sequence_reset_screen_verdict(&in_sequence, false, 5), None);
        let reset = screen_sequence_reset(&sequences, None, 1, || false);
        assert_eq!(
            sequence_reset_screen_verdict(&reset, false, 1),
            Some(InboundVerdict::Accepted { seq: 1 })
        );
        // Reset mode ignores its MsgSeqNum: even u64::MAX is not exhaustion.
        let reset = screen_sequence_reset(&sequences, None, u64::MAX, || false);
        assert_eq!(reset, ResetScreen::Reset);
        assert_eq!(
            sequence_reset_screen_verdict(&reset, false, u64::MAX),
            Some(InboundVerdict::Accepted { seq: u64::MAX })
        );
    }

    #[test]
    fn test_sequence_reset_decision_verdicts() {
        assert_eq!(
            sequence_reset_verdict(
                &ResetDecision::Apply {
                    new_seq: 9,
                    renumbers: false,
                    advances: true
                },
                false,
                5
            ),
            None
        );
        // An applied GapFill is accepted with the decision, once the cursor
        // has moved.
        assert_eq!(
            sequence_reset_verdict(
                &ResetDecision::Apply {
                    new_seq: 9,
                    renumbers: false,
                    advances: true
                },
                true,
                5
            ),
            Some(InboundVerdict::Accepted { seq: 5 })
        );
        for decision in [
            ResetDecision::MissingNewSeqNo,
            ResetDecision::FillNotAdvancing { new_seq: 5 },
            ResetDecision::ResetBelowExpected {
                new_seq: 2,
                expected: 5,
            },
        ] {
            assert_eq!(
                sequence_reset_verdict(&decision, true, 5),
                Some(InboundVerdict::Rejected {
                    seq: 5,
                    reason: InboundRefusal::InvalidSequenceReset
                })
            );
        }
    }

    #[test]
    fn test_capture_point_accessors() {
        let framed = CapturePoint::InboundFramed {
            kind: FrameKind::Handshake,
            seq: None,
            frame_id: Some(1),
        };
        assert_eq!(framed.frame_id(), Some(1));
        assert_eq!(framed.direction(), Direction::Inbound);
        assert_eq!(framed.kind(), FrameKind::Handshake);
        assert_eq!(framed.seq(), None);

        let verdict = CapturePoint::Inbound {
            verdict: InboundVerdict::Accepted { seq: 7 },
            frame_id: Some(3),
        };
        assert_eq!(verdict.frame_id(), Some(3));
        assert_eq!(CapturePoint::replayed(3).frame_id(), None);
        assert_eq!(verdict.direction(), Direction::Inbound);
        assert_eq!(verdict.kind(), FrameKind::Session);
        assert_eq!(verdict.seq(), Some(7));

        let replay = CapturePoint::replayed(3);
        assert_eq!(replay.direction(), Direction::Outbound);
        assert!(replay.is_resend());
        assert_eq!(replay.seq(), Some(3));
        assert!(CapturePoint::gap_filled(4).is_resend());

        let result = CapturePoint::OutboundResult {
            kind: FrameKind::Session,
            seq: None,
            result: WriteClass::NotSent,
        };
        assert_eq!(result.direction(), Direction::Outbound);
        assert!(!result.is_resend());
        assert_eq!(result.seq(), None);
    }

    #[test]
    fn test_a_sync_sink_receives_points_in_order() {
        struct Recorder(RefCell<Vec<(CapturePoint, Option<Vec<u8>>)>>);
        impl FrameCapture for Recorder {
            fn on_capture(&self, point: &CapturePoint, frame: Option<&[u8]>, _at: Instant) {
                self.0
                    .borrow_mut()
                    .push((*point, frame.map(<[u8]>::to_vec)));
            }
        }
        let sink = Recorder(RefCell::new(Vec::new()));
        let at = Instant::now();
        let sequences = expecting(1);
        let route = route_inbound(&sequences, &MsgType::Heartbeat, 1, || false);
        sink.on_capture(
            &CapturePoint::InboundFramed {
                kind: FrameKind::Session,
                seq: Some(1),
                frame_id: Some(1),
            },
            Some(b"35=0"),
            at,
        );
        if let Some(verdict) = inbound_verdict(&route, 1) {
            sink.on_capture(
                &CapturePoint::Inbound {
                    verdict,
                    frame_id: Some(1),
                },
                None,
                at,
            );
        }
        let points = sink.0.into_inner();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].1.as_deref(), Some(&b"35=0"[..]));
        assert_eq!(
            points[1].0,
            CapturePoint::Inbound {
                verdict: InboundVerdict::Accepted { seq: 1 },
                frame_id: Some(1),
            }
        );
    }
}
