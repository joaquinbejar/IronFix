/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! Sans-IO core, stage 4: the decisions of the Logout (5) handshake.
//!
//! A session ends gracefully through a Logout exchange: one side sends a
//! Logout and the other answers with its own. This module decides every step
//! of that exchange; the driver builds and writes the frames, keeps the
//! typestate session and runs the callbacks.
//!
//! - **Starting one.** [`check_logout_text`] screens the `Text` (58) a caller
//!   asks for (issue #69). [`decide_local_logout`] says whether a Logout of
//!   this session may still start, and [`LocalLogoutReason::text`] is the
//!   `Text` it carries. Once the Logout is handed to the output the session
//!   is [`LogoutPhase::Queued`]; [`decide_logout_advance`] moves it to
//!   [`LogoutPhase::Pending`] once the frame is written whole, and the logout
//!   timeout runs from that moment ([`logout_timed_out`](crate::sans_io::logout_timed_out),
//!   issue #126). A queued or pending session takes no new application
//!   message ([`LogoutPhase::accepts_application_messages`]).
//! - **Answering one.** [`decide_peer_logout`] decides what the
//!   counterparty's Logout means in each phase: it completes an exchange this
//!   session started (crossed, when ours was still being written), or it is
//!   owed a reply. A reply waits behind a resend this session owes, and
//!   [`OwedLogout`] records when the first Logout arrived, so the wait is
//!   bounded by the logout timeout (issues #79, #128): the driver checks
//!   [`owed_logout_due`] on its tick, before every resend step and between
//!   held frames.
//! - **Closing.** [`LogoutClose`] is the close-reason family of the exchange
//!   (issue #69): which kinds are graceful, and how a graceful close becomes
//!   [`LogoutClose::Unwritten`] when this session's own Logout never reached
//!   the stream whole ([`settle_close`], [`reply_close`]). Only a graceful
//!   close counts for `reset_on_logout` ([`close_resets`], issue #126), and so
//!   only a graceful close records the durable owed-reset marker of issue
//!   #111.

use crate::config::SessionConfig;
use std::time::{Duration, Instant};

/// The most bytes [`check_logout_text`] accepts for a Logout `Text` (58).
///
/// Driver contract: a driver that lets its caller choose the text of a
/// Logout refuses a longer one before anything is queued. Changing the bound
/// is a semver event.
pub const MAX_LOGOUT_TEXT_LEN: usize = 1024;

/// Why [`check_logout_text`] refused a Logout `Text` (58).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogoutTextError {
    /// The text is empty; a FIX field carries at least one byte.
    Empty,
    /// The text is longer than [`MAX_LOGOUT_TEXT_LEN`] bytes.
    TooLong,
    /// A byte is outside printable ASCII (0x20 to 0x7E): SOH or another
    /// control character would break the frame, and a non-ASCII text needs
    /// `EncodedText` (355).
    NotPrintableAscii,
}

/// Checks a Logout `Text` (58) a caller asks for: 1 to
/// [`MAX_LOGOUT_TEXT_LEN`] bytes of printable ASCII (0x20 to 0x7E).
///
/// The checks run in that order, so an empty text is [`LogoutTextError::Empty`]
/// and an over-long text is [`LogoutTextError::TooLong`] whatever its bytes.
///
/// # Errors
/// The first rule the text breaks.
pub fn check_logout_text(text: &str) -> Result<(), LogoutTextError> {
    if text.is_empty() {
        return Err(LogoutTextError::Empty);
    }
    if text.len() > MAX_LOGOUT_TEXT_LEN {
        return Err(LogoutTextError::TooLong);
    }
    if !text.bytes().all(|byte| (0x20..=0x7E).contains(&byte)) {
        return Err(LogoutTextError::NotPrintableAscii);
    }
    Ok(())
}

/// Where an Active session stands in a Logout exchange it started.
///
/// The driver keeps the typestate session (`Session<Active>` while
/// [`LogoutPhase::Active`] or [`LogoutPhase::Queued`],
/// `Session<LogoutPending>` while [`LogoutPhase::Pending`]) and summarises it
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogoutPhase {
    /// No Logout of this session has been handed to the output.
    Active,
    /// This session's Logout is in the output and not yet written whole. The
    /// session already behaves as one logging out, but the logout timeout
    /// has not started; the driver's write timeout bounds the wait.
    Queued,
    /// This session's Logout was written whole and awaits the counterparty's
    /// Logout, within the logout timeout from that moment.
    Pending,
}

impl LogoutPhase {
    /// Whether a new application message may still be sent. Nothing that
    /// takes a new number follows this session's own Logout.
    #[must_use]
    pub const fn accepts_application_messages(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether this session has started a Logout exchange of its own.
    #[must_use]
    pub const fn is_logging_out(self) -> bool {
        !self.accepts_application_messages()
    }
}

/// What a request to start this session's Logout comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalLogoutDecision {
    /// Send the Logout now.
    Send,
    /// A Logout of this session is already queued or sent: only the first
    /// counts, so nothing more goes on the wire and the first cause stands.
    AlreadyLoggingOut,
}

/// Decides whether a Logout of this session may start in `phase`. Used both
/// for a Logout the caller asks for and for one the engine starts (dropped
/// handles, an abandoned gap).
#[must_use]
pub const fn decide_local_logout(phase: LogoutPhase) -> LocalLogoutDecision {
    match phase {
        LogoutPhase::Active => LocalLogoutDecision::Send,
        LogoutPhase::Queued | LogoutPhase::Pending => LocalLogoutDecision::AlreadyLoggingOut,
    }
}

/// Why this session starts its own Logout, as far as the core needs it: the
/// `Text` (58) the Logout carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalLogoutReason<'a> {
    /// The caller asked for it, with an optional text.
    Requested {
        /// The text the caller asked for.
        text: Option<&'a str>,
    },
    /// Every handle to the session was dropped.
    HandlesDropped,
    /// A `ResendRequest` (2) of this session went unanswered for the attempt
    /// limit.
    ResendStalled {
        /// The first `MsgSeqNum` the counterparty never resent.
        expected: u64,
        /// How many requests went out for it.
        attempts: u32,
    },
}

impl LocalLogoutReason<'_> {
    /// The `Text` (58) this session's Logout carries: the caller's text, the
    /// stalled resend explained ([`resend_stalled_text`]), or none for
    /// dropped handles. An empty text is written as no `Text` by the driver.
    #[must_use]
    pub fn text(self) -> Option<String> {
        match self {
            Self::Requested { text } => text.map(str::to_owned),
            Self::HandlesDropped => None,
            Self::ResendStalled { expected, attempts } => {
                Some(resend_stalled_text(expected, attempts))
            }
        }
    }
}

/// The `Text` (58) of the Logout that abandons a gap at `expected` after
/// `attempts` requests. It names sequence numbers only.
#[must_use]
pub fn resend_stalled_text(expected: u64, attempts: u32) -> String {
    format!("resend of MsgSeqNum {expected} unanswered after {attempts} request(s)")
}

/// Whether a queued Logout has now been written whole, moving the session
/// from [`LogoutPhase::Queued`] to [`LogoutPhase::Pending`].
///
/// `take_written` reports (and consumes) the driver's "written whole" mark.
/// It is called only in [`LogoutPhase::Queued`], so the mark is never taken
/// in another phase. On `true` the driver performs the typestate transition
/// with the current `now`, which is where the logout timeout starts.
#[must_use]
pub fn decide_logout_advance(phase: LogoutPhase, take_written: impl FnOnce() -> bool) -> bool {
    match phase {
        LogoutPhase::Queued => take_written(),
        LogoutPhase::Active | LogoutPhase::Pending => false,
    }
}

/// A Logout the counterparty sent that this session has not answered yet,
/// because a resend it owes is still under way.
///
/// It keeps the arrival of the **first** such Logout: a counterparty that
/// keeps logging out cannot push the reply back (issue #128).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedLogout {
    since: Instant,
    text: Option<String>,
}

impl OwedLogout {
    /// A Logout that arrived at `now`, with its `Text` (58) already bounded
    /// by the driver (never parsed).
    #[must_use]
    pub const fn new(now: Instant, text: Option<String>) -> Self {
        Self { since: now, text }
    }

    /// When the first Logout arrived.
    #[must_use]
    pub const fn since(&self) -> Instant {
        self.since
    }

    /// The counterparty's `Text` (58).
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    /// Takes the counterparty's `Text` (58) for the close reason.
    #[must_use]
    pub fn into_text(self) -> Option<String> {
        self.text
    }

    /// Whether the reply has waited `logout_timeout` by `now`. A `now`
    /// earlier than the arrival counts as no time elapsed.
    #[must_use]
    pub fn is_due(&self, now: Instant, logout_timeout: Duration) -> bool {
        let waited = now
            .checked_duration_since(self.since)
            .unwrap_or(Duration::ZERO);
        waited >= logout_timeout
    }
}

/// Whether an owed reply has waited the logout timeout by `now`: what is
/// left of the resend is then dropped and the reply goes out at once.
///
/// Driver contract: checked on every tick, before every resend step and
/// between frames held back behind the resend, so no step writes past the
/// deadline.
#[must_use]
pub fn owed_logout_due(owed: Option<&OwedLogout>, now: Instant, logout_timeout: Duration) -> bool {
    owed.is_some_and(|owed| owed.is_due(now, logout_timeout))
}

/// What the counterparty's Logout means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerLogoutDecision {
    /// It completes the exchange this session started: the session closes
    /// as [`LogoutClose::Local`]. `crossed` is set when ours was still being
    /// written (the two Logouts crossed); the driver moves the typestate
    /// through `LogoutPending` at `now` to `Disconnected`, and what is left
    /// of ours is written out as the session closes.
    CompleteLocal {
        /// Our Logout was queued, not yet written whole.
        crossed: bool,
    },
    /// A resend this session owes is under way: the reply waits for it,
    /// bounded by the logout timeout ([`owed_logout_due`]). The session
    /// keeps resending and reading meanwhile.
    AwaitResend,
    /// Reply now with this session's Logout and close.
    Reply,
}

/// Decides what the counterparty's Logout means in `phase`, at `now`.
///
/// In [`LogoutPhase::Active`] the Logout is owed a reply: `owed` records the
/// first one (a repeated Logout keeps the first arrival and text, and `text`
/// is then not called), and the reply waits while `resend_in_progress`.
/// FIX gives the remote end the chance to fill any gap before it replies to
/// a Logout.
#[must_use]
pub fn decide_peer_logout(
    phase: LogoutPhase,
    owed: &mut Option<OwedLogout>,
    now: Instant,
    text: impl FnOnce() -> Option<String>,
    resend_in_progress: bool,
) -> PeerLogoutDecision {
    match phase {
        LogoutPhase::Pending => PeerLogoutDecision::CompleteLocal { crossed: false },
        LogoutPhase::Queued => PeerLogoutDecision::CompleteLocal { crossed: true },
        LogoutPhase::Active => {
            if owed.is_none() {
                *owed = Some(OwedLogout::new(now, text()));
            }
            if resend_in_progress {
                PeerLogoutDecision::AwaitResend
            } else {
                PeerLogoutDecision::Reply
            }
        }
    }
}

/// How far this session's reply to the counterparty's Logout got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogoutReplyWrite {
    /// The reply was handed to the output. Whether it was written whole is
    /// settled as the session closes ([`settle_close`]).
    Fed,
    /// Handing it over failed, but the stream had already taken the whole
    /// reply (a flush that failed after the write): the counterparty can
    /// decode it.
    WrittenBeforeFailure,
    /// The reply never reached the stream whole: it was dropped before it
    /// was framed, or feeding it failed.
    NotWritten,
}

/// The close-reason family of a Logout exchange (issue #69), and the
/// graceful rule.
///
/// The driver maps its own close reasons onto this family; every reason that
/// is not part of a Logout exchange is [`LogoutClose::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogoutClose {
    /// This session logged out and the counterparty answered, or the two
    /// Logouts crossed. Graceful.
    Local,
    /// The counterparty logged out and this session replied. Graceful.
    Peer,
    /// This session's Logout was written whole and no answer arrived within
    /// the logout timeout. Graceful: the Logout reached the stream.
    Timeout,
    /// A Logout exchange ended without this session's own Logout written
    /// whole. Not graceful.
    Unwritten,
    /// Not a Logout exchange (a timeout, a transport failure, a protocol
    /// violation, ...). Not graceful.
    Other,
}

impl LogoutClose {
    /// Whether the close is graceful: the Logout exchange happened and this
    /// session's own Logout was written whole.
    #[must_use]
    pub const fn is_graceful(self) -> bool {
        matches!(self, Self::Local | Self::Peer | Self::Timeout)
    }

    /// What a graceful close becomes when this session's own Logout was
    /// never written whole; any other close is unchanged.
    #[must_use]
    pub const fn unwritten(self) -> Self {
        match self {
            Self::Local | Self::Peer | Self::Timeout => Self::Unwritten,
            Self::Unwritten => Self::Unwritten,
            Self::Other => Self::Other,
        }
    }
}

/// The close a reply to the counterparty's Logout produces:
/// [`LogoutClose::Peer`] if it reached (or will be settled as reaching) the
/// stream, [`LogoutClose::Unwritten`] if it never did.
#[must_use]
pub const fn reply_close(write: LogoutReplyWrite) -> LogoutClose {
    match write {
        LogoutReplyWrite::Fed | LogoutReplyWrite::WrittenBeforeFailure => LogoutClose::Peer,
        LogoutReplyWrite::NotWritten => LogoutClose::Unwritten,
    }
}

/// Settles a close as the session ends: a graceful close whose own Logout is
/// still unwritten in the output (`own_logout_unwritten`) is not graceful.
#[must_use]
pub const fn settle_close(close: LogoutClose, own_logout_unwritten: bool) -> LogoutClose {
    if close.is_graceful() && own_logout_unwritten {
        close.unwritten()
    } else {
        close
    }
}

/// Whether the sequence numbers (and the stored messages) reset as the
/// session closes: always under `reset_on_disconnect`, and under
/// `reset_on_logout` only for a graceful close.
///
/// Driver contract: the durable owed-reset marker (issue #111) is recorded
/// exactly when this is true, before the reset is made, so a close that is
/// not graceful never records it under `reset_on_logout` alone.
#[must_use]
pub const fn close_resets(config: &SessionConfig, close: LogoutClose) -> bool {
    config.reset_on_disconnect || (close.is_graceful() && config.reset_on_logout)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(10);
    const PHASES: [LogoutPhase; 3] = [
        LogoutPhase::Active,
        LogoutPhase::Queued,
        LogoutPhase::Pending,
    ];
    const CLOSES: [LogoutClose; 5] = [
        LogoutClose::Local,
        LogoutClose::Peer,
        LogoutClose::Timeout,
        LogoutClose::Unwritten,
        LogoutClose::Other,
    ];

    // Transcriptions of the reactor logic before stage 4, kept verbatim in
    // shape, for the equivalence tests below.

    /// `Command::Logout`: only `Phase::Active` begins a Logout.
    fn old_begins_logout(phase: LogoutPhase) -> bool {
        matches!(phase, LogoutPhase::Active)
    }

    /// `begin_logout`'s text selection over `LogoutCause`.
    fn old_logout_text(reason: LocalLogoutReason<'_>) -> Option<String> {
        match reason {
            LocalLogoutReason::Requested { text } => text.map(str::to_owned),
            LocalLogoutReason::ResendStalled { expected, attempts } => Some(format!(
                "resend of MsgSeqNum {expected} unanswered after {attempts} request(s)"
            )),
            _ => None,
        }
    }

    /// `on_logout` before stage 4: (decision, owed after).
    fn old_on_logout(
        phase: LogoutPhase,
        owed: Option<(Instant, Option<String>)>,
        now: Instant,
        text: Option<String>,
        resending: bool,
    ) -> (PeerLogoutDecision, Option<(Instant, Option<String>)>) {
        match phase {
            LogoutPhase::Pending => (PeerLogoutDecision::CompleteLocal { crossed: false }, owed),
            LogoutPhase::Queued => (PeerLogoutDecision::CompleteLocal { crossed: true }, owed),
            LogoutPhase::Active => {
                let owed = owed.or(Some((now, text)));
                if resending {
                    (PeerLogoutDecision::AwaitResend, owed)
                } else {
                    (PeerLogoutDecision::Reply, owed)
                }
            }
        }
    }

    /// `owed_logout_due` before stage 4 (`Instant::duration_since`
    /// saturates at zero).
    fn old_owed_due(since: Option<Instant>, now: Instant, timeout: Duration) -> bool {
        since.is_some_and(|since| now.duration_since(since) >= timeout)
    }

    /// The close-time check and reset gate of the reactor before stage 4.
    fn old_close(graceful: bool, unwritten: bool, config: &SessionConfig) -> (bool, bool) {
        let graceful = graceful && !unwritten;
        (
            graceful,
            config.reset_on_disconnect || (graceful && config.reset_on_logout),
        )
    }

    #[test]
    fn test_logout_text_rules() {
        assert_eq!(check_logout_text(""), Err(LogoutTextError::Empty));
        assert_eq!(check_logout_text("bye"), Ok(()));
        assert_eq!(check_logout_text(&"x".repeat(MAX_LOGOUT_TEXT_LEN)), Ok(()));
        assert_eq!(
            check_logout_text(&"x".repeat(MAX_LOGOUT_TEXT_LEN + 1)),
            Err(LogoutTextError::TooLong)
        );
        // Length is checked before content.
        assert_eq!(
            check_logout_text(&"\u{1}".repeat(MAX_LOGOUT_TEXT_LEN + 1)),
            Err(LogoutTextError::TooLong)
        );
        for bad in ["a\u{1}b", "tab\there", "caf\u{e9}", "line\n", "\u{7f}"] {
            assert_eq!(
                check_logout_text(bad),
                Err(LogoutTextError::NotPrintableAscii),
                "{bad:?}"
            );
        }
        assert_eq!(check_logout_text(" ~"), Ok(()));
    }

    #[test]
    fn test_local_logout_starts_only_once_and_matches_the_old_rule() {
        for phase in PHASES {
            let decision = decide_local_logout(phase);
            assert_eq!(
                decision == LocalLogoutDecision::Send,
                old_begins_logout(phase)
            );
            assert_eq!(
                phase.accepts_application_messages(),
                decision == LocalLogoutDecision::Send
            );
            assert_eq!(
                phase.is_logging_out(),
                !phase.accepts_application_messages()
            );
        }
    }

    #[test]
    fn test_logout_text_matches_the_old_selection() {
        let reasons = [
            LocalLogoutReason::Requested { text: None },
            LocalLogoutReason::Requested { text: Some("eod") },
            LocalLogoutReason::HandlesDropped,
            LocalLogoutReason::ResendStalled {
                expected: 7,
                attempts: 3,
            },
            LocalLogoutReason::ResendStalled {
                expected: u64::MAX,
                attempts: u32::MAX,
            },
        ];
        for reason in reasons {
            assert_eq!(reason.text(), old_logout_text(reason), "{reason:?}");
        }
        assert_eq!(
            resend_stalled_text(7, 3),
            "resend of MsgSeqNum 7 unanswered after 3 request(s)"
        );
    }

    #[test]
    fn test_advance_takes_the_mark_only_when_queued() {
        for phase in PHASES {
            for written in [false, true] {
                let mut taken = false;
                let advanced = decide_logout_advance(phase, || {
                    taken = true;
                    written
                });
                assert_eq!(taken, phase == LogoutPhase::Queued);
                assert_eq!(advanced, phase == LogoutPhase::Queued && written);
            }
        }
    }

    #[test]
    fn test_peer_logout_completes_ours_or_is_owed_a_reply() {
        let t0 = Instant::now();
        let mut owed = None;
        assert_eq!(
            decide_peer_logout(LogoutPhase::Pending, &mut owed, t0, || None, false),
            PeerLogoutDecision::CompleteLocal { crossed: false }
        );
        assert_eq!(
            decide_peer_logout(LogoutPhase::Queued, &mut owed, t0, || None, true),
            PeerLogoutDecision::CompleteLocal { crossed: true }
        );
        assert!(owed.is_none(), "completing ours owes nothing");

        assert_eq!(
            decide_peer_logout(
                LogoutPhase::Active,
                &mut owed,
                t0,
                || Some("first".to_owned()),
                true
            ),
            PeerLogoutDecision::AwaitResend
        );
        // A repeated Logout keeps the first arrival and text.
        let later = t0 + Duration::from_secs(3);
        assert_eq!(
            decide_peer_logout(
                LogoutPhase::Active,
                &mut owed,
                later,
                || panic!("the text of a repeated Logout is not read"),
                true
            ),
            PeerLogoutDecision::AwaitResend
        );
        let first = owed.clone().expect("owed");
        assert_eq!(first.since(), t0);
        assert_eq!(first.text(), Some("first"));
        // Once the resend is done the reply goes out.
        assert_eq!(
            decide_peer_logout(LogoutPhase::Active, &mut owed, later, || None, false),
            PeerLogoutDecision::Reply
        );
        assert_eq!(first.into_text().as_deref(), Some("first"));
    }

    #[test]
    fn test_peer_logout_matches_the_old_reactor() {
        let t0 = Instant::now();
        let earlier = (t0, Some("earlier".to_owned()));
        for phase in PHASES {
            for prior in [None, Some(earlier.clone())] {
                for resending in [false, true] {
                    let now = t0 + Duration::from_secs(1);
                    let text = Some("peer".to_owned());
                    let (old, old_owed) =
                        old_on_logout(phase, prior.clone(), now, text.clone(), resending);
                    let mut owed = prior
                        .clone()
                        .map(|(since, text)| OwedLogout::new(since, text));
                    let new = decide_peer_logout(phase, &mut owed, now, || text, resending);
                    assert_eq!(new, old, "{phase:?} {prior:?} {resending}");
                    assert_eq!(
                        owed.map(|owed| (owed.since(), owed.into_text())),
                        old_owed,
                        "{phase:?} {prior:?} {resending}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_owed_logout_deadline_with_synthetic_time() {
        let t0 = Instant::now() + Duration::from_secs(100);
        let owed = OwedLogout::new(t0, None);
        assert!(!owed_logout_due(None, t0 + TIMEOUT, TIMEOUT));
        assert!(!owed_logout_due(Some(&owed), t0, TIMEOUT));
        assert!(!owed_logout_due(
            Some(&owed),
            t0 + TIMEOUT - Duration::from_nanos(1),
            TIMEOUT
        ));
        assert!(owed_logout_due(Some(&owed), t0 + TIMEOUT, TIMEOUT));
        // A `now` before the arrival is no time elapsed, not a panic.
        assert!(!owed_logout_due(
            Some(&owed),
            t0 - Duration::from_secs(50),
            TIMEOUT
        ));
        assert!(owed_logout_due(Some(&owed), t0, Duration::ZERO));
    }

    #[test]
    fn test_owed_logout_deadline_matches_the_old_reactor() {
        let t0 = Instant::now() + Duration::from_secs(100);
        let offsets_ms: [i64; 9] = [-50_000, -1, 0, 1, 9_999, 10_000, 10_001, 60_000, 0];
        for timeout in [Duration::ZERO, Duration::from_millis(1), TIMEOUT] {
            for since in [None, Some(t0)] {
                for offset in offsets_ms {
                    let delta = Duration::from_millis(offset.unsigned_abs());
                    let now = if offset < 0 { t0 - delta } else { t0 + delta };
                    let owed = since.map(|since| OwedLogout::new(since, None));
                    assert_eq!(
                        owed_logout_due(owed.as_ref(), now, timeout),
                        old_owed_due(since, now, timeout),
                        "{timeout:?} {since:?} {offset}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_close_family_graceful_rule() {
        for close in CLOSES {
            assert_eq!(
                close.is_graceful(),
                matches!(
                    close,
                    LogoutClose::Local | LogoutClose::Peer | LogoutClose::Timeout
                )
            );
            let unwritten = close.unwritten();
            assert!(!unwritten.is_graceful());
            assert_eq!(
                unwritten,
                if close == LogoutClose::Other {
                    LogoutClose::Other
                } else {
                    LogoutClose::Unwritten
                }
            );
        }
        assert_eq!(
            reply_close(LogoutReplyWrite::Fed),
            LogoutClose::Peer,
            "settled at close"
        );
        assert_eq!(
            reply_close(LogoutReplyWrite::WrittenBeforeFailure),
            LogoutClose::Peer
        );
        assert_eq!(
            reply_close(LogoutReplyWrite::NotWritten),
            LogoutClose::Unwritten
        );
    }

    #[test]
    fn test_only_a_graceful_close_resets_on_logout_and_matches_the_old_gate() {
        for reset_on_logout in [false, true] {
            for reset_on_disconnect in [false, true] {
                let (Ok(sender), Ok(target)) = (
                    ironfix_core::types::CompId::new("CLIENT"),
                    ironfix_core::types::CompId::new("VENUE"),
                ) else {
                    unreachable!("CLIENT and VENUE are valid CompIDs")
                };
                let mut config = SessionConfig::new(sender, target, "FIX.4.4");
                config.reset_on_logout = reset_on_logout;
                config.reset_on_disconnect = reset_on_disconnect;
                for close in CLOSES {
                    for unwritten in [false, true] {
                        let settled = settle_close(close, unwritten);
                        let (old_graceful, old_reset) =
                            old_close(close.is_graceful(), unwritten, &config);
                        assert_eq!(settled.is_graceful(), old_graceful);
                        assert_eq!(close_resets(&config, settled), old_reset);
                        if reset_on_logout && !reset_on_disconnect && !settled.is_graceful() {
                            assert!(!close_resets(&config, settled));
                        }
                    }
                }
            }
        }
    }
}
