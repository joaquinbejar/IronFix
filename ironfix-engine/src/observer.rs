/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! A capture hook for every frame a session reads and writes (issue #70,
//! ADR-0026).
//!
//! Attach a [`FrameObserver`] with `with_frame_observer` on the
//! [`Initiator`](crate::Initiator), the [`Acceptor`](crate::Acceptor) or the
//! [`EngineBuilder`](crate::EngineBuilder), and the engine hands it the exact
//! bytes of every frame, in wire order, with an [`Observation`]: the
//! direction, what kind of frame it is, its `MsgSeqNum` (34) when known, a
//! monotonic [`Instant`] and the session. It is what audit and replay need to
//! reconstruct a session byte for byte.
//!
//! # What is observed
//!
//! - **Inbound**: every frame that passes framing, handshake frames of both
//!   roles included, as soon as it is framed and **before** the session acts
//!   on it. A frame the session later rejects, drops (a malformed body, a
//!   possible duplicate, a `MsgSeqNum` too low) or closes the session over
//!   (the wrong CompID, a `SendingTime` out of tolerance) has been observed
//!   already. Bytes the codec skips as garbled while framing (a wrong
//!   `CheckSum` (10), a `BodyLength` (9) that does not match, bytes before
//!   `8=`) never become a frame and are **not** observed; the session counts
//!   them instead. A frame that frames but whose header or body does not
//!   decode is observed too. Frames an
//!   [`AcceptorRegistry`](crate::AcceptorRegistry) skips before it has routed
//!   a Logon to a session belong to no session and are not observed; the
//!   routed Logon is, by the session it is routed to. Frames read and dropped
//!   while a closing session writes out its last output are not observed.
//! - **Outbound**: every frame the session writes, handshake frames, live
//!   messages, replays and gap fills, Rejects and Logouts on failure paths,
//!   once it is built and **before** any byte of it goes to the stream. In an
//!   established session that is the moment it is appended to the write
//!   buffer, so [`FrameObserver::on_outbound`] means "queued for the wire",
//!   never "written". Whether the write then completed is reported by
//!   [`FrameObserver::on_outbound_result`].
//!
//! # Write results
//!
//! Every frame passed to [`FrameObserver::on_outbound`] is followed by
//! exactly one [`FrameObserver::on_outbound_result`] for it, carrying the
//! same `MsgSeqNum` and kind, while the session runs or as it closes:
//!
//! - [`OutboundResult::Written`] once a flush that covers the frame
//!   completed: the stream accepted every byte of it;
//! - [`OutboundResult::Unknown`] when a write was started and did not
//!   complete (a transport error, the write timeout, a closing session whose
//!   last flush did not drain): the counterparty may have read all, part or
//!   none of it. Unknown never collapses into not sent.
//!
//! A message that reached the session and was never fed to the stream (a
//! veto by `to_app_checked`, a body the engine will not frame, the throttle,
//! a store refusal, a message still queued or held when the session closes, a gap fill
//! `to_admin` left unframeable, a replay the codec refuses)
//! was never observed as outbound, and is reported by
//! [`OutboundResult::NotSent`] alone, with no `MsgSeqNum`: the engine
//! guarantees no byte of it reached the stream. A frame that was numbered and filed but then refused by the
//! codec (above `max_message_size`) is reported [`OutboundResult::Unknown`]
//! without having been observed, as its tracked send outcome is.
//!
//! The classes are the ones [`SendOutcome`] uses. A
//! reactor task dropped by a runtime shutting down reports nothing more.
//!
//! # Contract for the observer
//!
//! The observer is **synchronous and called inline on the session's reactor
//! task**, or on the task running the handshake. Every call delays this
//! session's reads, writes, heartbeats and timeout detection for as long as
//! it takes: it must not block, must not wait on I/O and must not take a lock
//! another task holds for long. Copy the bytes into a queue of your own (a
//! pre-allocated ring, a bounded channel) and do the heavy work elsewhere.
//!
//! The frame is a borrowed slice, valid only for the call. The engine
//! allocates nothing to make an observation, and with no observer attached a
//! frame costs one branch.
//!
//! **The observer must not panic.** The engine does not catch a panic from
//! it: the release profile is `panic = "abort"`, so a panic takes the whole
//! process down, and under unwinding it ends the session's task without a
//! close.
//!
//! The observer cannot change what the session does: it sees the frames and
//! nothing more.
//!
//! # Credentials
//!
//! **The observer receives raw bytes, credentials included.** A Logon can
//! carry `Password` (554), `NewPassword` (925) and `RawData` (96), and they
//! reach the observer exactly as they are on the wire. The engine never logs
//! a frame; redacting what the observer stores or logs is **the observer's
//! responsibility**.
//!
//! # Out of scope
//!
//! The timestamp is the engine's monotonic clock read at the observation
//! (Tokio's, so a paused-clock test sees paused time), not a kernel or NIC
//! receive or transmit timestamp.

use crate::application::SessionId;
use crate::outcome::{NotSentReason, SendOutcome, UnknownReason};
use ironfix_tagvalue::Decoder;
use std::sync::Arc;
use std::time::Instant;

/// Which way a frame travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Direction {
    /// Read from the counterparty.
    Inbound,
    /// Written to the counterparty.
    Outbound,
}

/// What kind of frame an [`Observation`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
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

/// What the engine knows about one observed frame, or one write result.
///
/// Borrowed for the call only. Fields are read through getters, so one added
/// later is not a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Observation<'a> {
    direction: Direction,
    kind: FrameKind,
    msg_seq_num: Option<u64>,
    at: Instant,
    session_id: &'a SessionId,
}

impl<'a> Observation<'a> {
    /// Builds an observation.
    #[must_use]
    pub(crate) const fn new(
        direction: Direction,
        kind: FrameKind,
        msg_seq_num: Option<u64>,
        at: Instant,
        session_id: &'a SessionId,
    ) -> Self {
        Self {
            direction,
            kind,
            msg_seq_num,
            at,
            session_id,
        }
    }

    /// Which way the frame travels.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// What kind of frame it is.
    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        self.kind
    }

    /// The frame's `MsgSeqNum` (34), when known: always for an outbound
    /// frame; for an inbound one, when its standard header carries a
    /// well-formed one (read before the session validates anything); `None`
    /// for an [`OutboundResult::NotSent`] message that was never numbered.
    #[must_use]
    pub const fn msg_seq_num(&self) -> Option<u64> {
        self.msg_seq_num
    }

    /// When the observation was made, on the engine's monotonic clock.
    #[must_use]
    pub const fn at(&self) -> Instant {
        self.at
    }

    /// The session the frame belongs to.
    #[must_use]
    pub const fn session_id(&self) -> &'a SessionId {
        self.session_id
    }
}

/// How the write of an observed outbound frame ended, or why a message was
/// never written. The outcome classes of [`SendOutcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutboundResult {
    /// A flush that covers the frame completed: the stream accepted every
    /// byte of it.
    Written,
    /// No byte of the message reached the stream. It was never passed to
    /// [`FrameObserver::on_outbound`].
    #[non_exhaustive]
    NotSent {
        /// Why it was not sent.
        reason: NotSentReason,
    },
    /// A write was started and did not complete: the counterparty may have
    /// read all, part or none of the frame.
    #[non_exhaustive]
    Unknown {
        /// What stopped the write.
        reason: UnknownReason,
    },
}

impl OutboundResult {
    /// The result a send outcome maps to, with the `MsgSeqNum` it carries.
    pub(crate) fn from_outcome(outcome: &SendOutcome) -> (Self, Option<u64>) {
        match outcome {
            SendOutcome::Sent { seq, .. } => (Self::Written, Some(*seq)),
            SendOutcome::NotSent { reason } => (
                Self::NotSent {
                    reason: reason.clone(),
                },
                None,
            ),
            SendOutcome::Unknown { seq, reason } => (Self::Unknown { reason: *reason }, Some(*seq)),
        }
    }
}

/// A capture hook for every frame a session reads and writes. See the
/// [module documentation](self) for what is observed, when, and the contract
/// an implementation must keep: it runs inline on the session's task, must
/// be cheap, must not block and must not panic, and it receives raw bytes,
/// credentials included.
pub trait FrameObserver: Send + Sync + 'static {
    /// Called with every inbound frame once it is framed, before the session
    /// acts on it.
    fn on_inbound(&self, frame: &[u8], observation: &Observation<'_>);

    /// Called with every outbound frame once it is built, before any byte of
    /// it goes to the stream. Followed by exactly one
    /// [`FrameObserver::on_outbound_result`] for it.
    fn on_outbound(&self, frame: &[u8], observation: &Observation<'_>);

    /// Called once per observed outbound frame when its write completed or
    /// failed, and once for every message that reached the session and was
    /// never written. Does nothing by default.
    fn on_outbound_result(&self, result: &OutboundResult, observation: &Observation<'_>) {
        let _ = (result, observation);
    }
}

/// An attached observer bound to the session it observes.
#[derive(Clone)]
pub(crate) struct Capture {
    /// The observer.
    observer: Arc<dyn FrameObserver>,
    /// The session every observation names.
    session_id: SessionId,
}

impl std::fmt::Debug for Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capture")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

/// The driver's monotonic time, as the reactor reads it (ADR-0002).
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

impl Capture {
    /// Binds `observer` to `session_id`, when there is an observer.
    #[must_use]
    pub(crate) fn bind(
        observer: Option<&Arc<dyn FrameObserver>>,
        session_id: &SessionId,
    ) -> Option<Self> {
        observer.map(|observer| Self {
            observer: Arc::clone(observer),
            session_id: session_id.clone(),
        })
    }

    /// Observes an inbound `frame` of `kind`.
    pub(crate) fn inbound(&self, frame: &[u8], kind: FrameKind) {
        let observation = Observation::new(
            Direction::Inbound,
            kind,
            peek_msg_seq_num(frame),
            now(),
            &self.session_id,
        );
        self.observer.on_inbound(frame, &observation);
    }

    /// Observes an outbound `frame` of `kind`, numbered `seq`.
    pub(crate) fn outbound(&self, frame: &[u8], kind: FrameKind, seq: u64) {
        let observation = Observation::new(
            Direction::Outbound,
            kind,
            Some(seq),
            now(),
            &self.session_id,
        );
        self.observer.on_outbound(frame, &observation);
    }

    /// Reports the write `result` of a frame of `kind`, numbered `seq`.
    pub(crate) fn result(&self, result: &OutboundResult, kind: FrameKind, seq: Option<u64>) {
        let observation = Observation::new(Direction::Outbound, kind, seq, now(), &self.session_id);
        self.observer.on_outbound_result(result, &observation);
    }

    /// Reports a send `outcome` that was never observed as a frame.
    pub(crate) fn unsent(&self, outcome: &SendOutcome, kind: FrameKind) {
        let (result, seq) = OutboundResult::from_outcome(outcome);
        self.result(&result, kind, seq);
    }
}

/// How many fields of the standard header are looked at for `MsgSeqNum`.
const HEADER_SCAN_FIELDS: usize = 16;

/// The `MsgSeqNum` (34) of `frame`, read from its first
/// [`HEADER_SCAN_FIELDS`] fields with the tag=value decoder's own field walk:
/// a `DATA` field (`SecureData` (91), `RawData` (96), ...) is skipped by the
/// count its `LENGTH` field declares, so a `34=` inside its bytes is never
/// read. `None` when 34 is not among those fields, is not a number, or does
/// not fit a `u64`, and as soon as a field does not decode. Allocates
/// nothing. Only an observation reads it; no decision does.
#[must_use]
fn peek_msg_seq_num(frame: &[u8]) -> Option<u64> {
    let mut decoder = Decoder::new(frame);
    for _ in 0..HEADER_SCAN_FIELDS {
        let field = decoder.next_field().ok()??;
        if field.tag().value() == 34 {
            let value = field.as_bytes();
            if value.is_empty() {
                return None;
            }
            return value.iter().try_fold(0u64, |acc, byte| {
                if !byte.is_ascii_digit() {
                    return None;
                }
                acc.checked_mul(10)?.checked_add(u64::from(byte - b'0'))
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peek_msg_seq_num_reads_the_header_field() {
        let frame = b"8=FIX.4.4\x019=5\x0135=0\x0149=A\x0156=B\x0134=42\x0110=000\x01";
        assert_eq!(peek_msg_seq_num(frame), Some(42));
    }

    #[test]
    fn test_peek_msg_seq_num_refuses_what_is_not_a_number() {
        assert_eq!(peek_msg_seq_num(b"8=FIX.4.4\x0134=4x\x01"), None);
        assert_eq!(peek_msg_seq_num(b"8=FIX.4.4\x0134=\x01"), None);
        assert_eq!(peek_msg_seq_num(b"8=FIX.4.4\x0135=0\x01"), None);
        assert_eq!(
            peek_msg_seq_num(b"8=FIX.4.4\x0134=99999999999999999999999\x01"),
            None
        );
    }

    #[test]
    fn test_peek_msg_seq_num_never_reads_inside_a_data_field() {
        // SecureDataLen (90) / SecureData (91) ahead of the real 34.
        let frame = b"8=FIX.4.4\x019=5\x0135=5\x0190=18\x0191=opaque\x0134=777\x01tail\x0134=2\x01";
        assert_eq!(peek_msg_seq_num(frame), Some(2));
        // RawDataLength (95) / RawData (96) and no real 34 at all.
        let frame = b"8=FIX.4.4\x019=5\x0135=5\x0195=18\x0196=opaque\x0134=777\x01tail\x0152=x\x01";
        assert_eq!(peek_msg_seq_num(frame), None);
    }

    #[test]
    fn test_peek_msg_seq_num_does_not_take_a_tag_ending_in_34() {
        assert_eq!(peek_msg_seq_num(b"8=FIX.4.4\x01134=7\x0134=3\x01"), Some(3));
    }

    #[test]
    fn test_frame_kind_is_replay() {
        assert!(FrameKind::Replay.is_replay());
        assert!(FrameKind::GapFill.is_replay());
        assert!(!FrameKind::Session.is_replay());
        assert!(!FrameKind::Handshake.is_replay());
    }

    #[test]
    fn test_outbound_result_from_outcome_keeps_the_class() {
        let (result, seq) = OutboundResult::from_outcome(&SendOutcome::Unknown {
            seq: 9,
            reason: UnknownReason::Transport,
        });
        assert_eq!(
            result,
            OutboundResult::Unknown {
                reason: UnknownReason::Transport
            }
        );
        assert_eq!(seq, Some(9));
        let (result, seq) = OutboundResult::from_outcome(&SendOutcome::NotSent {
            reason: NotSentReason::LogoutPending,
        });
        assert!(matches!(result, OutboundResult::NotSent { .. }));
        assert_eq!(seq, None);
    }
}
