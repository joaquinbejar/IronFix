/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! The report of inbound messages the application may not have seen
//! (issue #105, ADR-0030).
//!
//! Inbound application delivery is **at most once**. The engine persists the
//! next target `MsgSeqNum` (34) before it acts on an inbound message (ADR-0005),
//! so the counterparty is never asked for a message again once it has been
//! accepted; a crash, or a dispatcher aborted at close, between that persist
//! and `from_app` returning loses the message to the application. The engine
//! does not redeliver it. It **reports** it, through
//! [`Application::on_inbound_lost`](crate::Application::on_inbound_lost), as
//! one [`InboundLoss`]: the `MsgSeqNum` span the application may not have
//! seen.
//!
//! # What the span names
//!
//! A span, not a list: `first..=last` runs from just past the inbound
//! application watermark (the highest number up to which every accepted
//! inbound message was acted on, see
//! [`MessageStore::app_watermark`](ironfix_store::MessageStore::app_watermark))
//! to the last number accepted. It can include administrative messages that
//! were processed in between, and it can include application messages whose
//! `from_app` had returned but whose watermark write had not landed when the
//! process died. It never leaves out a message that did not reach `from_app`.
//!
//! The report carries numbers only, never a frame: the engine keeps no inbound
//! journal, which is why it can report the span and not redeliver it.

use std::fmt;

/// When the engine found an [`InboundLoss`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum InboundLossCause {
    /// At the start of a session, from the attached store: the previous
    /// session, in this process or one that crashed, accepted messages that
    /// its application watermark does not cover.
    FoundAtStart,
    /// At the close of a session, when the application dispatcher did not
    /// finish within its drain timeout and was aborted, or stopped after a
    /// failed watermark write.
    DispatcherStopped,
}

impl fmt::Display for InboundLossCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FoundAtStart => f.write_str("found at session start"),
            Self::DispatcherStopped => f.write_str("application dispatcher stopped at close"),
        }
    }
}

/// An inbound `MsgSeqNum` (34) span the application may not have seen.
///
/// See the [module documentation](self) for what the span covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InboundLoss {
    /// First `MsgSeqNum` of the span.
    first: u64,
    /// Last `MsgSeqNum` of the span, inclusive.
    last: u64,
    /// When the engine found it.
    cause: InboundLossCause,
}

impl InboundLoss {
    /// The span above `watermark` up to `next_target - 1`, or `None` when
    /// there is none: the watermark is 0 (none recorded), or covers every
    /// number below `next_target`.
    ///
    /// A watermark of 0 means the store holds none for this stream (a store
    /// without the feature, or a stream whose first watermark write has not
    /// landed); the engine writes one before any application message of a
    /// stream is delivered, so nothing is reported for it.
    #[must_use]
    pub(crate) fn between(
        watermark: u64,
        next_target: u64,
        cause: InboundLossCause,
    ) -> Option<Self> {
        // The span is the sans-IO core's (issue #91, stage 5).
        let (first, last) = ironfix_session::inbound_loss_span(watermark, next_target)?;
        Some(Self { first, last, cause })
    }

    /// The first `MsgSeqNum` (34) of the span.
    #[must_use]
    pub const fn first(&self) -> u64 {
        self.first
    }

    /// The last `MsgSeqNum` (34) of the span, inclusive.
    #[must_use]
    pub const fn last(&self) -> u64 {
        self.last
    }

    /// When the engine found the loss.
    #[must_use]
    pub const fn cause(&self) -> InboundLossCause {
        self.cause
    }
}

impl fmt::Display for InboundLoss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "inbound MsgSeqNum {}..={} may not have reached the application ({})",
            self.first, self.last, self.cause
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_between_names_the_span_above_the_watermark() {
        let loss = InboundLoss::between(4, 8, InboundLossCause::FoundAtStart);
        assert_eq!(
            loss.map(|loss| (loss.first(), loss.last(), loss.cause())),
            Some((5, 7, InboundLossCause::FoundAtStart))
        );
    }

    #[test]
    fn test_between_reports_nothing_when_the_watermark_covers_everything() {
        assert_eq!(
            InboundLoss::between(7, 8, InboundLossCause::FoundAtStart),
            None
        );
        // A watermark above the target is stale (a reset it outlived): no
        // span.
        assert_eq!(
            InboundLoss::between(50, 2, InboundLossCause::FoundAtStart),
            None
        );
        // No watermark recorded.
        assert_eq!(
            InboundLoss::between(0, 9, InboundLossCause::FoundAtStart),
            None
        );
        // A target of 0 names nothing.
        assert_eq!(
            InboundLoss::between(3, 0, InboundLossCause::DispatcherStopped),
            None
        );
        // The boundary: a watermark at u64::MAX has no number above it.
        assert_eq!(
            InboundLoss::between(u64::MAX, u64::MAX, InboundLossCause::FoundAtStart),
            None
        );
    }

    #[test]
    fn test_display_carries_numbers_only() {
        let loss = InboundLoss::between(2, 5, InboundLossCause::DispatcherStopped);
        assert_eq!(
            loss.map(|loss| loss.to_string()).as_deref(),
            Some(
                "inbound MsgSeqNum 3..=4 may not have reached the application \
                 (application dispatcher stopped at close)"
            )
        );
    }
}
