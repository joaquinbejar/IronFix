/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! Why a session ended: the typed close reason the engine reports to the
//! [`Application`](crate::Application) and the [`Connection`](crate::Connection).
//!
//! Every way a session can end maps to one [`CloseReason`]. The reactor
//! records it once, as the session closes, and hands it to
//! [`Application::on_session_closed`](crate::Application::on_session_closed)
//! before [`Connection::wait_closed`](crate::Connection::wait_closed)
//! returns; [`Connection::close_reason`](crate::Connection::close_reason)
//! reads it afterwards. A dial that fails after `on_create` has run reports
//! [`CloseReason::ConnectFailed`], and a Logon handshake that fails reports
//! [`CloseReason::LogonFailed`], to the application; the caller gets
//! the detailed [`EngineError`](crate::EngineError) from `connect` or
//! `serve`, and no `Connection` exists. A handshake whose future the caller
//! drops (cancelled, for example by a `tokio::time::timeout` around
//! `connect`) gets no close callback: there is no `async` drop to run it
//! from, so an application that tracks `on_create` must treat its own
//! cancellation as the end of that session.
//!
//! # Graceful or not
//!
//! [`CloseReason::is_graceful`] is the engine's own graceful flag, the one
//! that decides whether `reset_on_logout` resets the sequence numbers: true
//! only when the Logout exchange happened and this session's own Logout (its
//! request, or its reply) was written whole. A Logout exchange whose own
//! Logout never left the write buffer is reported as
//! [`CloseReason::LogoutUnwritten`], and is not graceful: the counterparty
//! may see a disconnect without a Logout, which is what triggers a venue's
//! cancel on disconnect.
//!
//! # What a reason carries
//!
//! Structured data only: sequence numbers, a tag, a size, an
//! [`std::io::ErrorKind`]. The one free text is the `Text` (58) of a Logout,
//! the counterparty's (bounded to [`MAX_PEER_TEXT_LEN`] characters, each one
//! outside printable ASCII replaced with `?`, never parsed)
//! or the one this session sent. No reason carries a frame or any part of
//! one: `Password` (554), `NewPassword` (925) and `RawData` (96) cannot
//! appear in it.

use crate::tls::TlsFailure;
use ironfix_session::sequence::SequenceCounter;
use std::fmt;
use std::time::Duration;

/// The most characters of a counterparty's Logout `Text` (58) a
/// [`CloseReason`] keeps. The text is escaped character by character: each
/// one outside printable ASCII (0x20 to 0x7E) becomes `?`, so the kept text
/// is ASCII and at most this many bytes; characters past the limit are
/// dropped.
pub const MAX_PEER_TEXT_LEN: usize = 1024;

/// Who started a Logout exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum LogoutInitiator {
    /// This session sent the first Logout.
    Local,
    /// The counterparty sent the first Logout.
    Peer,
}

/// Why this session sent its own Logout.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogoutCause {
    /// [`Connection::logout`](crate::Connection::logout) or
    /// [`Connection::logout_with_text`](crate::Connection::logout_with_text)
    /// asked for it.
    #[non_exhaustive]
    Requested {
        /// The `Text` (58) the caller asked for, when one was given. A
        /// `to_admin` callback can change or remove tag 58 before the Logout
        /// is framed, so this is the requested text, not necessarily the
        /// text on the wire.
        text: Option<String>,
    },
    /// Every [`Connection`](crate::Connection) handle was dropped.
    HandlesDropped,
    /// A `ResendRequest` (2) of this session went unanswered for
    /// [`SessionConfig::resend_attempt_limit`](ironfix_session::SessionConfig::resend_attempt_limit)
    /// attempts.
    #[non_exhaustive]
    ResendStalled {
        /// The first `MsgSeqNum` the counterparty never resent.
        expected: u64,
        /// How many requests went out for it.
        attempts: u32,
    },
}

/// Why a session ended.
///
/// See the [module documentation](self). Every variant is
/// `#[non_exhaustive]`, and so is the enum: new close paths (a TLS failure,
/// for one) and new fields are added in minor releases, so match with a
/// wildcard arm and `..`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    /// This session logged out and the counterparty acknowledged (or the two
    /// Logouts crossed). Graceful.
    #[non_exhaustive]
    LocalLogout {
        /// Why this session logged out.
        cause: LogoutCause,
        /// The `Text` (58) of the counterparty's Logout, if it carried one.
        peer_text: Option<String>,
    },
    /// The counterparty logged out and this session replied. Graceful.
    #[non_exhaustive]
    PeerLogout {
        /// The `Text` (58) of the counterparty's Logout, if it carried one.
        text: Option<String>,
    },
    /// This session's Logout was sent and no acknowledgement arrived within
    /// [`SessionConfig::logout_timeout`](ironfix_session::SessionConfig::logout_timeout).
    /// Graceful, as it has always been: the Logout reached the stream.
    #[non_exhaustive]
    LogoutTimeout {
        /// Why this session logged out.
        cause: LogoutCause,
    },
    /// A Logout exchange ended but this session's own Logout (its request,
    /// or its reply) never reached the stream whole: it was still in the
    /// write buffer, or the reply was dropped before it was framed (a
    /// `to_admin` callback left it unframeable) or failed to feed. Not
    /// graceful: `reset_on_logout` does not reset, and the counterparty may
    /// have seen no Logout from this session.
    #[non_exhaustive]
    LogoutUnwritten {
        /// Who started the exchange.
        initiator: LogoutInitiator,
        /// Why this session logged out, when it started the exchange.
        cause: Option<LogoutCause>,
        /// The `Text` (58) of the counterparty's Logout, if it carried one.
        peer_text: Option<String>,
    },
    /// A `TestRequest` (1) went unanswered: the counterparty fell silent.
    #[non_exhaustive]
    HeartbeatTimeout {},
    /// Output waited for the write timeout with the stream accepting none
    /// of it: the counterparty stopped reading.
    #[non_exhaustive]
    WriteTimeout {
        /// The configured write timeout.
        timeout: Duration,
    },
    /// The counterparty closed the transport without a Logout.
    #[non_exhaustive]
    TransportClosed {},
    /// Reading from or writing to the transport failed.
    #[non_exhaustive]
    TransportError {
        /// The I/O error's kind, when the failure surfaced as an
        /// [`std::io::Error`]. `None` when it surfaced through the framing
        /// codec, which keeps the error's text but not its kind.
        kind: Option<std::io::ErrorKind>,
    },
    /// An inbound frame exceeded
    /// [`SessionConfig::max_message_size`](ironfix_session::SessionConfig::max_message_size)
    /// (or an outbound one could not be framed under it). An Active session
    /// sent a Logout with `Text` (58) "message too large" first.
    #[non_exhaustive]
    MessageTooLarge {
        /// The frame's size in bytes.
        size: usize,
        /// The ceiling.
        max_size: usize,
    },
    /// The framing codec reported an error the stream cannot continue past
    /// other than an oversized frame or an I/O failure.
    #[non_exhaustive]
    FramingError {},
    /// An inbound `MsgSeqNum` (34) below the expected one without
    /// `PossDupFlag` (43) = Y: the streams diverged. A Logout carrying the
    /// numbers in `Text` (58) was sent first.
    #[non_exhaustive]
    SequenceTooLow {
        /// The `MsgSeqNum` this session expected.
        expected: u64,
        /// The `MsgSeqNum` it received.
        received: u64,
    },
    /// [`SessionConfig::garbled_frame_limit`](ironfix_session::SessionConfig::garbled_frame_limit)
    /// garbled frames arrived within its window.
    #[non_exhaustive]
    GarbledFrameLimit {
        /// The configured frame count.
        max: u32,
        /// The configured window.
        window: Duration,
    },
    /// An inbound message carried the wrong counterparty identity (49/56,
    /// or 50/57, 142/143 when configured). A Reject and a Logout were sent
    /// first.
    #[non_exhaustive]
    IdentityMismatch {
        /// The tag that did not match.
        tag: u32,
    },
    /// An inbound `SendingTime` (52) was missing, malformed or outside the
    /// configured tolerance. A Reject and a Logout were sent first.
    #[non_exhaustive]
    SendingTime {},
    /// The attached store failed (or timed out) under
    /// [`StoreFailurePolicy::CloseSession`](crate::StoreFailurePolicy::CloseSession),
    /// or reported itself corrupted during a resend. No Logout is sent.
    #[non_exhaustive]
    StoreFailure {},
    /// A sequence counter reached `u64::MAX`; the session closes rather than
    /// wrap it.
    #[non_exhaustive]
    SequenceExhausted {
        /// Which counter.
        counter: SequenceCounter,
    },
    /// The inbound application queue was full: `from_app` is not keeping up.
    #[non_exhaustive]
    ApplicationQueueFull {},
    /// The application dispatcher task stopped.
    #[non_exhaustive]
    DispatcherStopped {},
    /// [`Initiator::connect`](crate::Initiator::connect) could not dial the
    /// counterparty after `on_create` had run: the TCP connect failed or
    /// timed out. Reported to
    /// [`Application::on_session_closed`](crate::Application::on_session_closed)
    /// only; the caller receives the [`EngineError`](crate::EngineError).
    #[non_exhaustive]
    ConnectFailed {
        /// The connect error's kind; `None` when it timed out.
        kind: Option<std::io::ErrorKind>,
        /// Whether the connect timeout ran out.
        timed_out: bool,
    },
    /// The Logon handshake failed after `on_create` had run (the transport
    /// was already connected). Reported to
    /// [`Application::on_session_closed`](crate::Application::on_session_closed)
    /// only: no `Connection` exists, and the caller of `connect`, `establish`
    /// or `serve` receives the detailed [`EngineError`](crate::EngineError).
    #[non_exhaustive]
    LogonFailed {},
    /// TLS failed after `on_create` had run: the TLS handshake of
    /// `Initiator::connect_tls` failed or
    /// timed out, or
    /// [`Application::authorize_peer`](crate::Application::authorize_peer)
    /// refused the counterparty on any entry point that proves a peer.
    /// Reported to
    /// [`Application::on_session_closed`](crate::Application::on_session_closed)
    /// only; the caller receives [`EngineError::Tls`](crate::EngineError::Tls).
    /// A failed TLS handshake on an acceptor runs before `on_create` and is
    /// not reported here. The session never reached Active.
    #[non_exhaustive]
    Tls {
        /// Which TLS step failed.
        failure: TlsFailure,
    },
    /// The engine reached a state it does not expect. Logged with detail.
    #[non_exhaustive]
    Internal {},
}

impl CloseReason {
    /// Whether the session ended through a Logout exchange in which this
    /// session's own Logout was written: the condition for
    /// `reset_on_logout`.
    #[must_use]
    pub const fn is_graceful(&self) -> bool {
        matches!(
            self,
            Self::LocalLogout { .. } | Self::PeerLogout { .. } | Self::LogoutTimeout { .. }
        )
    }

    /// Whether the session reached Active before it ended: false only for
    /// [`CloseReason::ConnectFailed`], [`CloseReason::LogonFailed`] and
    /// [`CloseReason::Tls`]. The default
    /// [`Application::on_session_closed`](crate::Application::on_session_closed)
    /// forwards to `on_logout` exactly when this is true.
    #[must_use]
    pub const fn was_active(&self) -> bool {
        !matches!(
            self,
            Self::ConnectFailed { .. } | Self::LogonFailed { .. } | Self::Tls { .. }
        )
    }

    /// The reason a graceful close becomes when this session's own Logout
    /// was never written whole. Any other reason is returned unchanged.
    #[must_use]
    pub(crate) fn unwritten(self) -> Self {
        match self {
            Self::LocalLogout { cause, peer_text } => Self::LogoutUnwritten {
                initiator: LogoutInitiator::Local,
                cause: Some(cause),
                peer_text,
            },
            Self::PeerLogout { text } => Self::LogoutUnwritten {
                initiator: LogoutInitiator::Peer,
                cause: None,
                peer_text: text,
            },
            Self::LogoutTimeout { cause } => Self::LogoutUnwritten {
                initiator: LogoutInitiator::Local,
                cause: Some(cause),
                peer_text: None,
            },
            other => other,
        }
    }
}

/// Keeps at most [`MAX_PEER_TEXT_LEN`] characters of a counterparty's text,
/// each one outside printable ASCII (0x20 to 0x7E) replaced with `?`, so no
/// control character, newline or non-ASCII character reaches a log line or
/// the application; an empty text is no text. The result is ASCII, so its
/// length in bytes is its length in characters.
#[must_use]
pub(crate) fn bounded_peer_text(text: Option<&str>) -> Option<String> {
    let text = text.filter(|text| !text.is_empty())?;
    Some(
        text.chars()
            .take(MAX_PEER_TEXT_LEN)
            .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
            .collect(),
    )
}

impl fmt::Display for LogoutCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested { text: None } => f.write_str("requested"),
            Self::Requested { text: Some(text) } => write!(f, "requested: {text}"),
            Self::HandlesDropped => f.write_str("every connection handle dropped"),
            Self::ResendStalled { expected, attempts } => write!(
                f,
                "resend of MsgSeqNum {expected} unanswered after {attempts} request(s)"
            ),
        }
    }
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalLogout { cause, peer_text } => {
                write!(f, "logout complete ({cause})")?;
                write_peer_text(f, peer_text.as_deref())
            }
            Self::PeerLogout { text } => {
                f.write_str("logout by counterparty")?;
                write_peer_text(f, text.as_deref())
            }
            Self::LogoutTimeout { cause } => write!(f, "logout ack timeout ({cause})"),
            Self::LogoutUnwritten {
                initiator,
                peer_text,
                ..
            } => {
                let by = match initiator {
                    LogoutInitiator::Local => "this session",
                    LogoutInitiator::Peer => "the counterparty",
                };
                write!(
                    f,
                    "logout started by {by} ended before this session's Logout was written"
                )?;
                write_peer_text(f, peer_text.as_deref())
            }
            Self::HeartbeatTimeout {} => {
                f.write_str("heartbeat timeout: no response to TestRequest")
            }
            Self::WriteTimeout { timeout } => write!(
                f,
                "write timeout: no output accepted for {} ms",
                timeout.as_millis()
            ),
            Self::TransportClosed {} => f.write_str("transport closed by peer"),
            Self::TransportError { kind: Some(kind) } => write!(f, "transport error: {kind}"),
            Self::TransportError { kind: None } => f.write_str("transport error"),
            Self::MessageTooLarge { size, max_size } => {
                write!(f, "message too large: {size} bytes, limit {max_size}")
            }
            Self::FramingError {} => f.write_str("fatal framing error"),
            Self::SequenceTooLow { expected, received } => write!(
                f,
                "MsgSeqNum too low: expected {expected}, received {received}"
            ),
            Self::GarbledFrameLimit { max, window } => write!(
                f,
                "garbled frame limit reached: {max} garbled inbound frames within {} ms",
                window.as_millis()
            ),
            Self::IdentityMismatch { tag } => {
                write!(f, "counterparty identity mismatch on tag {tag}")
            }
            Self::SendingTime {} => f.write_str("SendingTime (52) problem"),
            Self::StoreFailure {} => f.write_str("store failure under the fail-closed policy"),
            Self::SequenceExhausted { counter } => {
                write!(f, "sequence counter exhausted: {counter}")
            }
            Self::ApplicationQueueFull {} => f.write_str(
                "application queue full: the application is not consuming inbound messages fast \
                 enough",
            ),
            Self::DispatcherStopped {} => f.write_str("application dispatcher stopped"),
            Self::ConnectFailed {
                timed_out: true, ..
            } => f.write_str("connect timed out"),
            Self::ConnectFailed {
                kind: Some(kind), ..
            } => write!(f, "connect failed: {kind}"),
            Self::ConnectFailed { .. } => f.write_str("connect failed"),
            Self::LogonFailed {} => f.write_str("Logon handshake failed"),
            Self::Tls { failure } => write!(f, "{failure}"),
            Self::Internal {} => f.write_str("internal error"),
        }
    }
}

/// Appends `: text` for a counterparty's text, when there is one.
fn write_peer_text(f: &mut fmt::Formatter<'_>, text: Option<&str>) -> fmt::Result {
    match text {
        Some(text) => write!(f, ": {text}"),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graceful_reasons() {
        let cause = LogoutCause::Requested { text: None };
        assert!(
            CloseReason::LocalLogout {
                cause: cause.clone(),
                peer_text: None
            }
            .is_graceful()
        );
        assert!(CloseReason::PeerLogout { text: None }.is_graceful());
        assert!(
            CloseReason::LogoutTimeout {
                cause: cause.clone()
            }
            .is_graceful()
        );
        assert!(!CloseReason::TransportClosed {}.is_graceful());
        assert!(!CloseReason::HeartbeatTimeout {}.is_graceful());
        let unwritten = CloseReason::LocalLogout {
            cause,
            peer_text: Some("bye".into()),
        }
        .unwritten();
        assert!(!unwritten.is_graceful());
        assert!(matches!(
            unwritten,
            CloseReason::LogoutUnwritten {
                initiator: LogoutInitiator::Local,
                cause: Some(_),
                ..
            }
        ));
        assert!(matches!(
            CloseReason::PeerLogout { text: None }.unwritten(),
            CloseReason::LogoutUnwritten {
                initiator: LogoutInitiator::Peer,
                ..
            }
        ));
        assert_eq!(
            CloseReason::HeartbeatTimeout {}.unwritten(),
            CloseReason::HeartbeatTimeout {}
        );
    }

    #[test]
    fn test_was_active() {
        assert!(!CloseReason::LogonFailed {}.was_active());
        let tls = CloseReason::Tls {
            failure: TlsFailure::PeerRejected,
        };
        assert!(!tls.was_active());
        assert!(!tls.is_graceful());
        assert_eq!(tls.to_string(), "TLS peer refused by the application");
        assert!(CloseReason::TransportClosed {}.was_active());
    }

    #[test]
    fn test_bounded_peer_text() {
        assert_eq!(bounded_peer_text(None), None);
        assert_eq!(bounded_peer_text(Some("")), None);
        assert_eq!(bounded_peer_text(Some("bye")).as_deref(), Some("bye"));
        let long = "x".repeat(MAX_PEER_TEXT_LEN + 10);
        let cut = bounded_peer_text(Some(&long)).unwrap_or_default();
        assert_eq!(cut.len(), MAX_PEER_TEXT_LEN);
        let wide = "é".repeat(MAX_PEER_TEXT_LEN + 1);
        let cut = bounded_peer_text(Some(&wide)).unwrap_or_default();
        assert_eq!(cut, "?".repeat(MAX_PEER_TEXT_LEN));
    }

    #[test]
    fn test_bounded_peer_text_escapes_unprintable_characters() {
        assert_eq!(
            bounded_peer_text(Some("a\u{1}b\nc\rd\te\u{7f}f caf\u{e9}")).as_deref(),
            Some("a?b?c?d?e?f caf?")
        );
        assert_eq!(bounded_peer_text(Some("~ !")).as_deref(), Some("~ !"));
    }

    #[test]
    fn test_display_carries_numbers() {
        let text = CloseReason::SequenceTooLow {
            expected: 7,
            received: 3,
        }
        .to_string();
        assert_eq!(text, "MsgSeqNum too low: expected 7, received 3");
    }
}
