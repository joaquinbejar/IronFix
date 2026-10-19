/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Per-message send outcomes, reported by
//! [`Connection::send_tracked`](crate::Connection::send_tracked).
//!
//! [`Connection::send`](crate::Connection::send) returns once the message is
//! queued for the session reactor. `send_tracked` waits for the message's
//! fate and reports it as one of three classes, which never collapse into one
//! another:
//!
//! - [`SendOutcome::Sent`]: the frame was written to the stream by a flush
//!   that completed. It carries the `MsgSeqNum` (34) and `SendingTime` (52)
//!   the counterparty reads, and whether the store filed it.
//! - [`SendOutcome::NotSent`]: the engine guarantees that **no byte** of the
//!   frame reached the stream, and no `MsgSeqNum` was spent on it. The
//!   [`NotSentReason`] says why: refused by the application, not a message
//!   the session carries, refused by the store, refused by the session's
//!   outbound throttle, or discarded because the session ended first.
//! - [`SendOutcome::Unknown`]: the frame was built and its `MsgSeqNum`
//!   spent (it was being filed, or it was in the session's write buffer)
//!   when the session stopped before a flush covering it completed: the
//!   counterparty may have read all of it, part of it, or none. A number is
//!   spent when its frame is buffered, so a frame buffered behind output the
//!   counterparty was not taking is `Unknown` too, never `NotSent`.
//!   [`UnknownReason`] says what stopped it.
//!
//! # `Unknown` means the order may be live
//!
//! Do not resubmit a message that reported `Unknown` blindly: the
//! counterparty may have read and acted on it. Reconcile it by its `ClOrdID`
//! (11) after the next Logon, through the `ExecutionReport` (8) the
//! counterparty sends for it or an `OrderStatusRequest` (H). If it must be
//! resubmitted, reuse its `ClOrdID` and set `PossResend` (97) = Y, so the
//! counterparty can recognise a duplicate.
//!
//! The number stays spent. The frame under it is replayed, with
//! `PossDupFlag` (43) = Y, only when **all** of these hold:
//!
//! - it was filed: a store was attached and the filing succeeded (the frame
//!   may also have been filed when filing was interrupted);
//! - the store was not reset when the session closed
//!   ([`SessionConfig::reset_on_disconnect`](ironfix_session::SessionConfig::reset_on_disconnect),
//!   or [`SessionConfig::reset_on_logout`](ironfix_session::SessionConfig::reset_on_logout)
//!   on a graceful close);
//! - the next Logon does not reset the sequence with `ResetSeqNumFlag` (141)
//!   = Y ([`SessionConfig::reset_on_logon`](ironfix_session::SessionConfig::reset_on_logon),
//!   a daily reset, or a reset the engine owes after a failed store write);
//! - the store still holds it: [`ironfix_store::MemoryStore`] does not
//!   survive a restart, and an [`ironfix_store::FileStore`] that does not sync
//!   every write may lose it to an operating-system crash;
//! - the counterparty asks for it, with a `ResendRequest` (2) or a
//!   `NextExpectedMsgSeqNum` (789) at or below it.
//!
//! Otherwise a `ResendRequest` covering it is answered with a
//! `SequenceReset`-GapFill, or never made.
//!
//! # Ordering guarantee
//!
//! `Sent` resolves only after the frame went through the store step of the
//! write order (see the [`persistence`](crate::persistence) module) **and**
//! a flush that covers it completed. The session writes through a buffer:
//! a frame is appended to it, and the buffer is written out, and the stream
//! flushed, while the session goes on reading. A completed flush resolves
//! every tracked frame it wrote at once, in the order they were sent. Its
//! `filed` field says whether the store confirmed it filed the frame: it is
//! false without a store, and false under
//! [`StoreFailurePolicy::Continue`](crate::StoreFailurePolicy::Continue) when
//! the filing failed or timed out and the frame went out anyway. False means
//! filing was not confirmed, not that the store lacks the frame: a store can
//! save it and still return an error, so a `ResendRequest` covering it is
//! answered with the frame if the store holds it and with a
//! `SequenceReset`-GapFill if it does not. Flushed means handed to the stream in full: the
//! bytes may still sit in an operating-system or TLS buffer, and nothing at
//! the FIX layer says the counterparty has processed them.
//!
//! # Constructing outcomes
//!
//! Every type here is `#[non_exhaustive]`, and so is every variant that
//! carries data: code outside this crate matches outcomes but cannot build
//! them, so a test double of a `Connection` cannot yet return one.

use crate::application::RejectReason;
use crate::error::EngineError;
use crate::throttle::BudgetId;
use ironfix_core::error::EncodeError;
use ironfix_core::types::Timestamp;
use tokio::sync::oneshot;

/// What became of one application message handed to
/// [`Connection::send_tracked`](crate::Connection::send_tracked).
///
/// See the [module documentation](self) for the three classes, what to do
/// with an `Unknown`, and the ordering guarantee. The enum and each of its
/// variants are `#[non_exhaustive]`: match a variant with `{ .. }` so that a
/// field added later is not a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use = "a send outcome says whether the message reached the counterparty; an Unknown one \
              may be live and must be reconciled"]
pub enum SendOutcome {
    /// The frame was written to the stream by a flush that completed.
    #[non_exhaustive]
    Sent {
        /// The `MsgSeqNum` (34) the frame carries.
        seq: u64,
        /// The `SendingTime` (52) the frame carries, at the precision the
        /// session writes on the wire: whole seconds on FIX 4.0 and FIX 4.1,
        /// milliseconds on every later version.
        sending_time: Timestamp,
        /// Whether the attached store confirmed it filed the frame. True means
        /// the store accepted it, so a `ResendRequest` (2) covering it replays
        /// it while the store holds it. False means filing was **not
        /// confirmed**: always without a store, and under
        /// [`StoreFailurePolicy::Continue`](crate::StoreFailurePolicy::Continue)
        /// when the store call returned an error or timed out and the frame
        /// went out anyway. A store can fail after it saved the frame, so an
        /// unconfirmed frame may or may not be replayed: a `ResendRequest`
        /// covering it is answered with the frame if the store holds it, and
        /// with a `SequenceReset`-GapFill if it does not.
        filed: bool,
    },
    /// No byte of the frame reached the stream, and no `MsgSeqNum` was spent
    /// on it.
    #[non_exhaustive]
    NotSent {
        /// Why the message was not sent.
        reason: NotSentReason,
    },
    /// The frame was numbered, and was being filed or waiting in the write
    /// buffer, when the session stopped before a flush covering it
    /// completed: the counterparty may have read all, part or none of it.
    /// **The order may be live**: do not resubmit it blindly (see the
    /// [module documentation](self)).
    ///
    /// The `MsgSeqNum` stays spent. The frame is replayed under it, with
    /// `PossDupFlag` (43) = Y, only if it was filed, the store was not reset
    /// at the close or by the next Logon's `ResetSeqNumFlag` (141), the store
    /// still holds it, and the counterparty asks for it. The session closes:
    /// a stream whose write did not complete cannot carry the next frame.
    #[non_exhaustive]
    Unknown {
        /// The `MsgSeqNum` (34) spent on the frame.
        seq: u64,
        /// What stopped the write.
        reason: UnknownReason,
    },
}

impl SendOutcome {
    /// Returns the `MsgSeqNum` (34) the message was given, if one was spent:
    /// `Some` for [`SendOutcome::Sent`] and [`SendOutcome::Unknown`], `None`
    /// for [`SendOutcome::NotSent`].
    #[must_use]
    pub const fn seq(&self) -> Option<u64> {
        match self {
            Self::Sent { seq, .. } | Self::Unknown { seq, .. } => Some(*seq),
            Self::NotSent { .. } => None,
        }
    }

    /// Returns whether a flush that covers the frame completed.
    #[must_use]
    pub const fn is_sent(&self) -> bool {
        matches!(self, Self::Sent { .. })
    }

    /// The [`SendOutcome::NotSent`] outcome for `reason`.
    pub(crate) const fn not_sent(reason: NotSentReason) -> Self {
        Self::NotSent { reason }
    }
}

/// Why a message reported [`SendOutcome::NotSent`]: no byte of it reached the
/// stream and no `MsgSeqNum` was spent on it.
///
/// `#[non_exhaustive]`, like every variant here but
/// [`NotSentReason::SequenceExhausted`] and [`NotSentReason::LogoutPending`]:
/// match it with a wildcard arm and the variants with `{ .. }`, so that a
/// reason, or a field, added later is not a breaking change. The reasons that
/// say the session ended carry no data yet; a typed close reason (#69) is the
/// candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotSentReason {
    /// [`Application::to_app_checked`](crate::Application::to_app_checked)
    /// refused the message. It was refused before a `MsgSeqNum` was spent and
    /// before the store was touched, so the next message takes the number
    /// this one would have had. The session carries on.
    #[non_exhaustive]
    Vetoed {
        /// The reason the application gave.
        reason: RejectReason,
    },
    /// The message is not one the engine will frame, as handed in or as
    /// `to_app_checked` left it: an administrative `MsgType`, a body field
    /// repeating a tag the engine stamps itself, or a value with no legal
    /// wire form. These are the errors [`Connection::send`](crate::Connection::send)
    /// returns before queuing; a body the callback broke is refused the same
    /// way after it. The session carries on.
    #[non_exhaustive]
    Invalid {
        /// What is wrong with it. It names the tag, and for an
        /// administrative `MsgType` the `MsgType` (35) value, but never quotes
        /// the value of any other field: a body can carry `Password` (554).
        detail: String,
        /// The tag at fault, when there is one: 35 for an administrative
        /// `MsgType`, the field's tag otherwise.
        tag: Option<u32>,
    },
    /// The attached store failed to file the frame (or to persist the next
    /// sender number), or did not answer within the store timeout, under
    /// [`StoreFailurePolicy::CloseSession`](crate::StoreFailurePolicy::CloseSession).
    /// Nothing was written and no number spent, and the session closes.
    ///
    /// Under [`StoreFailurePolicy::Continue`](crate::StoreFailurePolicy::Continue)
    /// a store failure does not stop the frame: it is written anyway and
    /// reports [`SendOutcome::Sent`] with `filed` false.
    ///
    /// **Across a restart.** A failed or timed-out store write leaves the
    /// store's state unknown: the frame may have been filed after all. Within
    /// the process the engine owes the next session a sequence reset, which
    /// erases it. That record lives in memory only (issue #111), so after a
    /// restart a store that did file the frame can replay it in answer to a
    /// `ResendRequest`, under the number this session never spent.
    #[non_exhaustive]
    StoreRefused {
        /// Whether the store's state after the failure is unknown. Always
        /// true today: the store contract gives a failed write no way to say
        /// it changed nothing.
        state_unknown: bool,
    },
    /// The sender sequence counter has reached `u64::MAX`, so no number is
    /// left for the frame. The session closes rather than wrap the counter.
    SequenceExhausted,
    /// The session was already closed, or closed before the message could be
    /// queued. It never reached the session reactor.
    #[non_exhaustive]
    SessionClosed {},
    /// This session's own Logout had been framed when the reactor reached
    /// the message: the session is on its way out, and a new application
    /// message would arrive after the Logout the counterparty has already
    /// seen. Also reported when the session closed with the message waiting
    /// behind a resend that the counterparty asked for after that Logout. A
    /// message still in the outbound queue at close, with no resend under
    /// way, reports [`NotSentReason::Discarded`] instead, Logout or not.
    LogoutPending,
    /// The session ended while the message was waiting in the outbound queue
    /// and no resend was under way, including when this session's own Logout
    /// had been framed ahead of it.
    #[non_exhaustive]
    Discarded {},
    /// The session ended while the message was waiting behind a resend this
    /// session owed the counterparty (the answer to its `ResendRequest`, or
    /// the resend its `NextExpectedMsgSeqNum` (789) asked for): nothing that
    /// takes a new number is written in the middle of a resend.
    #[non_exhaustive]
    DiscardedBehindResend {},
    /// The session's outbound throttle refused the message (see
    /// [`crate::throttle`]): its budget had no token, and either the budget's
    /// policy is [`ThrottlePolicy::Refuse`](crate::ThrottlePolicy::Refuse)
    /// or its [`ThrottlePolicy::Queue`](crate::ThrottlePolicy::Queue) already
    /// held `max_depth` messages. It was refused before
    /// [`Application::to_app_checked`](crate::Application::to_app_checked)
    /// ran, before a `MsgSeqNum` was peeked and before the store was touched.
    /// The session carries on.
    #[non_exhaustive]
    Throttled {
        /// The budget that refused it.
        budget: BudgetId,
    },
    /// The message was held by the outbound throttle, waiting for a token,
    /// when this session's own Logout was framed or the session ended: no
    /// message held by the throttle is written after the Logout.
    #[non_exhaustive]
    DiscardedByThrottle {
        /// The budget that held it.
        budget: BudgetId,
    },
}

impl NotSentReason {
    /// The reason a message the engine will not frame reports, from the
    /// check that refused it: [`Connection::send`](crate::Connection::send)'s
    /// own errors, or the recheck after `to_app_checked`.
    #[must_use]
    pub(crate) fn invalid(error: &EngineError) -> Self {
        let tag = match error {
            EngineError::ReservedMsgType { .. } => Some(35),
            EngineError::ReservedTag { tag }
            | EngineError::InvalidField { tag, .. }
            | EngineError::MissingRequiredField { tag, .. } => Some(*tag),
            EngineError::Encode(err) => encode_tag(err),
            // The outbound checks raise nothing else; a tag cannot be named.
            _ => None,
        };
        Self::Invalid {
            detail: error.to_string(),
            tag,
        }
    }

    /// The reason a body the encoder refused reports.
    #[must_use]
    pub(crate) fn unencodable(error: &EncodeError) -> Self {
        Self::Invalid {
            detail: error.to_string(),
            tag: encode_tag(error),
        }
    }
}

/// The tag an encoder refusal names, if it names one.
#[must_use]
const fn encode_tag(error: &EncodeError) -> Option<u32> {
    match error {
        EncodeError::MissingRequiredField { tag }
        | EncodeError::InvalidFieldValue { tag, .. }
        | EncodeError::FieldTooLong { tag, .. } => Some(*tag),
        // `EncodeError` is another crate's non-exhaustive enum; a buffer
        // overflow, or a variant it adds later, names no tag.
        _ => None,
    }
}

/// What stopped a frame that reported [`SendOutcome::Unknown`].
///
/// `#[non_exhaustive]`: match it with a wildcard arm, so that a reason added
/// later is not a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnknownReason {
    /// The waiting output made no progress for the session's write timeout
    /// (`with_write_timeout` on the `Initiator` or the `Acceptor`): the
    /// counterparty stopped reading. Also reported for the closing session's
    /// last flush when it stops progressing.
    WriteTimeout,
    /// The stream failed while the frame was waiting to be written or being
    /// written, or the codec refused the frame after it was numbered and
    /// filed.
    Transport,
    /// The session reactor stopped after the frame was numbered, while it
    /// was being filed or written: its Tokio runtime shut down, or an
    /// internal consistency check on the sequence counter failed.
    Interrupted,
}

/// How far a tracked frame has got: what a write that stops now leaves the
/// counterparty with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Not numbered yet: nothing filed, nothing written.
    Queued,
    /// Numbered `seq` and being filed: the store may hold it.
    Filing(u64),
    /// Numbered `seq`, filed, and fed to the write buffer, waiting for the
    /// flush that writes it.
    Writing(u64),
}

impl Stage {
    /// The number spent on the frame, once it has one.
    const fn seq(self) -> Option<u64> {
        match self {
            Self::Queued => None,
            Self::Filing(seq) | Self::Writing(seq) => Some(seq),
        }
    }
}

/// The outcome of a frame that stopped once numbered: unknown under `seq`,
/// or not sent if it never got a number.
const fn stopped(seq: Option<u64>, reason: UnknownReason) -> SendOutcome {
    match seq {
        Some(seq) => SendOutcome::Unknown { seq, reason },
        None => SendOutcome::not_sent(NotSentReason::Discarded {}),
    }
}

/// The reactor's end of one tracked send: resolves the caller's
/// [`SendOutcome`] exactly once.
///
/// Created only by [`Connection::send_tracked`](crate::Connection::send_tracked),
/// so a plain `send` carries none and allocates nothing for it. A receipt
/// dropped without being resolved still answers, from what it knows: a frame
/// that was numbered (being filed or written) reports [`SendOutcome::Unknown`]
/// with [`UnknownReason::Interrupted`], any other
/// [`NotSentReason::Discarded`]. That covers the paths that never reach an
/// explicit resolution: the outbound queue dropped with the reactor, and a
/// reactor task dropped mid-write by a runtime shutting down. A caller
/// therefore never waits forever, and a frame that may have been filed or
/// written never reports `NotSent`.
#[derive(Debug)]
pub(crate) struct Receipt {
    /// The caller's end; taken when the outcome is sent.
    tx: Option<oneshot::Sender<SendOutcome>>,
    /// How far the frame has got.
    stage: Stage,
}

impl Receipt {
    /// A new receipt and the receiver its outcome arrives on.
    #[must_use]
    pub(crate) fn new() -> (Self, oneshot::Receiver<SendOutcome>) {
        let (tx, rx) = oneshot::channel();
        (
            Self {
                tx: Some(tx),
                stage: Stage::Queued,
            },
            rx,
        )
    }

    /// Records that the frame numbered `seq` is about to be filed: from here
    /// on, a frame that stops is [`SendOutcome::Unknown`] unless the store
    /// refused it.
    pub(crate) const fn filing(&mut self, seq: u64) {
        self.stage = Stage::Filing(seq);
    }

    /// Records that the frame numbered `seq` has been fed to the write
    /// buffer: from here on, a frame no completed flush covered is
    /// [`SendOutcome::Unknown`].
    pub(crate) const fn writing(&mut self, seq: u64) {
        self.stage = Stage::Writing(seq);
    }

    /// Resolves the outcome. A caller that stopped waiting is not an error.
    pub(crate) fn resolve(mut self, outcome: SendOutcome) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(outcome);
        }
    }

    /// Resolves the outcome of a frame that `error` stopped on its way to the
    /// stream.
    ///
    /// Every variant is named, so a new one has to be placed here. Only the
    /// first group can stop a frame: what the store step raises (before the
    /// store is touched, a refusal, or a number spent out of turn) and what
    /// the write raises.
    pub(crate) fn fail(self, error: &EngineError) {
        let seq = self.stage.seq();
        let outcome = match error {
            // Checked before the store is touched: nothing filed or spent.
            EngineError::SequenceExhausted(_) => {
                SendOutcome::not_sent(NotSentReason::SequenceExhausted)
            }
            // The store refused under the fail-closed policy: nothing was
            // written or spent, whatever the store now holds.
            EngineError::Store(_) => SendOutcome::not_sent(NotSentReason::StoreRefused {
                state_unknown: true,
            }),
            // Raised after the frame was filed and a number spent.
            EngineError::Sequence(_) => stopped(seq, UnknownReason::Interrupted),
            // Raised by the write.
            EngineError::WriteTimeout(_) => stopped(seq, UnknownReason::WriteTimeout),
            EngineError::Codec(_) | EngineError::Io(_) => stopped(seq, UnknownReason::Transport),
            // Never raised between numbering a frame and writing it: they
            // belong to the handshakes, the builders and the caller's checks.
            EngineError::Decode(_)
            | EngineError::Encode(_)
            | EngineError::Config(_)
            | EngineError::ConnectTimeout(_)
            | EngineError::LogonTimeout(_)
            | EngineError::LogonRejected { .. }
            | EngineError::HeartbeatInterval { .. }
            | EngineError::ApplVersion { .. }
            | EngineError::NextExpectedMsgSeqNum { .. }
            | EngineError::UnexpectedMessage { .. }
            | EngineError::InvalidInitialSequence { .. }
            | EngineError::InitialSequenceBelowStore { .. }
            | EngineError::IdentityMismatch { .. }
            | EngineError::UnroutableLogon { .. }
            | EngineError::UnknownSession { .. }
            | EngineError::SessionLimit { .. }
            | EngineError::Lookup(_)
            | EngineError::BeginStringMismatch { .. }
            | EngineError::SendingTime { .. }
            | EngineError::UnsupportedVersion { .. }
            | EngineError::ReservedMsgType { .. }
            | EngineError::ReservedTag { .. }
            | EngineError::InvalidField { .. }
            | EngineError::MissingRequiredField { .. }
            | EngineError::Closed
            | EngineError::Configuration(_) => stopped(seq, UnknownReason::Interrupted),
        };
        self.resolve(outcome);
    }
}

impl Drop for Receipt {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(stopped(self.stage.seq(), UnknownReason::Interrupted));
        }
    }
}

/// Resolves `receipt`, if there is one, with the outcome `outcome` builds.
///
/// The outcome is built only when a receipt exists, so a plain `send` pays
/// nothing for it (a [`NotSentReason::Invalid`] detail is a formatted
/// string).
pub(crate) fn resolve(receipt: Option<Receipt>, outcome: impl FnOnce() -> SendOutcome) {
    if let Some(receipt) = receipt {
        receipt.resolve(outcome());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironfix_core::error::StoreError;
    use ironfix_session::sequence::{SequenceCounter, SequenceExhausted};
    use std::time::Duration;

    /// Receives an outcome that must already have been sent.
    #[track_caller]
    fn received(mut rx: oneshot::Receiver<SendOutcome>) -> SendOutcome {
        match rx.try_recv() {
            Ok(outcome) => outcome,
            Err(err) => panic!("the outcome must have been sent: {err:?}"),
        }
    }

    #[test]
    fn test_receipt_resolve_delivers_the_outcome() {
        let (receipt, rx) = Receipt::new();
        let sent = SendOutcome::Sent {
            seq: 7,
            sending_time: Timestamp::EPOCH,
            filed: true,
        };
        receipt.resolve(sent.clone());
        assert_eq!(received(rx), sent);
    }

    #[test]
    fn test_receipt_dropped_while_queued_is_discarded() {
        let (receipt, rx) = Receipt::new();
        drop(receipt);
        assert_eq!(
            received(rx),
            SendOutcome::not_sent(NotSentReason::Discarded {}),
            "a message the reactor never reached is not sent"
        );
    }

    #[test]
    fn test_receipt_dropped_mid_filing_is_unknown_never_not_sent() {
        let (mut receipt, rx) = Receipt::new();
        receipt.filing(11);
        drop(receipt);
        assert_eq!(
            received(rx),
            SendOutcome::Unknown {
                seq: 11,
                reason: UnknownReason::Interrupted,
            },
            "the store may hold a frame whose filing was interrupted"
        );
    }

    #[test]
    fn test_receipt_dropped_mid_write_is_unknown_never_not_sent() {
        let (mut receipt, rx) = Receipt::new();
        receipt.filing(12);
        receipt.writing(12);
        drop(receipt);
        assert_eq!(
            received(rx),
            SendOutcome::Unknown {
                seq: 12,
                reason: UnknownReason::Interrupted,
            }
        );
    }

    #[test]
    fn test_receipt_fail_in_the_store_step_is_not_sent() {
        let (mut receipt, rx) = Receipt::new();
        receipt.filing(3);
        receipt.fail(&EngineError::Store(StoreError::Io("refused".to_string())));
        assert_eq!(
            received(rx),
            SendOutcome::not_sent(NotSentReason::StoreRefused {
                state_unknown: true
            })
        );

        let (mut receipt, rx) = Receipt::new();
        receipt.filing(u64::MAX);
        receipt.fail(&EngineError::SequenceExhausted(SequenceExhausted {
            counter: SequenceCounter::Sender,
        }));
        assert_eq!(
            received(rx),
            SendOutcome::not_sent(NotSentReason::SequenceExhausted)
        );
    }

    #[test]
    fn test_receipt_fail_on_a_number_spent_out_of_turn_is_unknown() {
        let (mut receipt, rx) = Receipt::new();
        receipt.filing(4);
        receipt.fail(&EngineError::Sequence("moved".to_string()));
        assert_eq!(
            received(rx),
            SendOutcome::Unknown {
                seq: 4,
                reason: UnknownReason::Interrupted,
            },
            "filed and spent: never not sent"
        );
    }

    #[test]
    fn test_receipt_fail_after_the_write_started_is_unknown() {
        let (mut receipt, rx) = Receipt::new();
        receipt.writing(5);
        receipt.fail(&EngineError::WriteTimeout(Duration::from_secs(1)));
        assert_eq!(
            received(rx),
            SendOutcome::Unknown {
                seq: 5,
                reason: UnknownReason::WriteTimeout,
            }
        );

        let (mut receipt, rx) = Receipt::new();
        receipt.writing(6);
        receipt.fail(&EngineError::Io(std::io::ErrorKind::BrokenPipe.into()));
        assert_eq!(
            received(rx),
            SendOutcome::Unknown {
                seq: 6,
                reason: UnknownReason::Transport,
            }
        );
    }

    #[test]
    fn test_receipt_fail_before_a_number_is_not_sent() {
        let (receipt, rx) = Receipt::new();
        receipt.fail(&EngineError::Closed);
        assert_eq!(
            received(rx),
            SendOutcome::not_sent(NotSentReason::Discarded {}),
            "nothing numbered, nothing filed"
        );
    }

    #[test]
    fn test_receipt_whose_caller_stopped_waiting_resolves_quietly() {
        let (receipt, rx) = Receipt::new();
        drop(rx);
        receipt.resolve(SendOutcome::not_sent(NotSentReason::LogoutPending));
    }

    #[test]
    fn test_resolve_without_a_receipt_builds_nothing() {
        resolve(None, || panic!("no receipt, so no outcome is built"));
    }

    #[test]
    fn test_invalid_names_the_tag_and_never_the_value() {
        let reason = NotSentReason::invalid(&EngineError::InvalidField {
            tag: 554,
            reason: "value contains the SOH delimiter".to_string(),
        });
        assert!(matches!(
            reason,
            NotSentReason::Invalid { tag: Some(554), .. }
        ));
        let reason = NotSentReason::invalid(&EngineError::ReservedMsgType {
            msg_type: "0".to_string(),
        });
        assert!(matches!(
            reason,
            NotSentReason::Invalid { tag: Some(35), .. }
        ));
        let reason = NotSentReason::unencodable(&EncodeError::BufferOverflow {
            needed: 2,
            available: 1,
        });
        assert!(matches!(reason, NotSentReason::Invalid { tag: None, .. }));
    }

    #[test]
    fn test_send_outcome_seq_and_is_sent() {
        let sent = SendOutcome::Sent {
            seq: 3,
            sending_time: Timestamp::EPOCH,
            filed: false,
        };
        assert_eq!(sent.seq(), Some(3));
        assert!(sent.is_sent());

        let unknown = SendOutcome::Unknown {
            seq: 4,
            reason: UnknownReason::Transport,
        };
        assert_eq!(unknown.seq(), Some(4), "an unknown frame spent its number");
        assert!(!unknown.is_sent());

        let not_sent = SendOutcome::not_sent(NotSentReason::Vetoed {
            reason: RejectReason::new(0, "risk limit"),
        });
        assert_eq!(not_sent.seq(), None, "nothing was spent");
        assert!(!not_sent.is_sent());
    }
}
