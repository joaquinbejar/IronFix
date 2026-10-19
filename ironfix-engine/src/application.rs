/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Application callback interface.
//!
//! This module defines the callback interface for handling FIX messages,
//! following the QuickFIX pattern with async support.

use crate::outbound::OutboundMessage;
use async_trait::async_trait;
use ironfix_core::message::RawMessage;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Session identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId {
    /// BeginString (FIX version).
    pub begin_string: String,
    /// Sender CompID.
    pub sender_comp_id: String,
    /// Target CompID.
    pub target_comp_id: String,
    /// Optional sender sub ID.
    pub sender_sub_id: Option<String>,
    /// Optional target sub ID.
    pub target_sub_id: Option<String>,
}

impl SessionId {
    /// Creates a new session ID.
    #[must_use]
    pub fn new(
        begin_string: impl Into<String>,
        sender_comp_id: impl Into<String>,
        target_comp_id: impl Into<String>,
    ) -> Self {
        Self {
            begin_string: begin_string.into(),
            sender_comp_id: sender_comp_id.into(),
            target_comp_id: target_comp_id.into(),
            sender_sub_id: None,
            target_sub_id: None,
        }
    }

    /// Sets the sender sub ID.
    #[must_use]
    pub fn with_sender_sub_id(mut self, sub_id: impl Into<String>) -> Self {
        self.sender_sub_id = Some(sub_id.into());
        self
    }

    /// Sets the target sub ID.
    #[must_use]
    pub fn with_target_sub_id(mut self, sub_id: impl Into<String>) -> Self {
        self.target_sub_id = Some(sub_id.into());
        self
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}->{}",
            self.begin_string, self.sender_comp_id, self.target_comp_id
        )
    }
}

/// Reason for rejecting a message.
///
/// Returned by [`Application::from_admin`] and [`Application::from_app`] to
/// reject an inbound message (the engine answers with a session-level Reject
/// carrying it), and by [`Application::to_app_checked`] to veto an outbound
/// one (the sender sees it in
/// [`NotSentReason::Vetoed`](crate::outcome::NotSentReason::Vetoed)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectReason {
    /// Rejection reason code.
    pub code: u32,
    /// Human-readable rejection text.
    pub text: String,
    /// Reference tag that caused the rejection.
    pub ref_tag: Option<u32>,
}

impl RejectReason {
    /// Creates a new rejection reason.
    #[must_use]
    pub fn new(code: u32, text: impl Into<String>) -> Self {
        Self {
            code,
            text: text.into(),
            ref_tag: None,
        }
    }

    /// Sets the reference tag.
    #[must_use]
    pub const fn with_ref_tag(mut self, tag: u32) -> Self {
        self.ref_tag = Some(tag);
        self
    }
}

/// Application callback interface for handling FIX messages.
///
/// Implement this trait to receive callbacks for session events
/// and message processing.
///
/// # Where each callback runs
///
/// [`Application::to_admin`] and [`Application::to_app_checked`] (which by
/// default forwards to [`Application::to_app`]) run **inline in the session
/// reactor**, on the message the engine is about to encode and number. That
/// is what makes their mutations effective, and it is why they cannot be
/// moved off the reactor: the message they hand back is the one that gets a
/// sequence number. A slow implementation delays the session's own timers.
///
/// [`Application::from_admin`] also runs inline, because its verdict decides
/// what the session does next — whether a `SequenceReset` is applied, whether
/// the Logon is accepted — and that decision cannot be taken before the
/// verdict exists.
///
/// [`Application::from_app`] runs on a **separate dispatcher task** fed by a
/// bounded queue, so a slow handler no longer stalls socket reads, heartbeat
/// generation or timeout detection. Messages reach it in ascending
/// `MsgSeqNum` order. The only consequence of a rejection — a session-level
/// Reject carrying `RefSeqNum` — is emitted by the reactor when it next polls,
/// so it may follow messages that arrived after the rejected one. See
/// [`Initiator::with_app_queue_capacity`](crate::Initiator::with_app_queue_capacity)
/// for the queue depth and what happens when it fills.
#[async_trait]
pub trait Application: Send + Sync {
    /// Called when a session is created.
    ///
    /// # Arguments
    /// * `session_id` - The session identifier
    async fn on_create(&self, session_id: &SessionId);

    /// Called on successful logon.
    ///
    /// # Arguments
    /// * `session_id` - The session identifier
    async fn on_logon(&self, session_id: &SessionId);

    /// Called on logout.
    ///
    /// # Arguments
    /// * `session_id` - The session identifier
    async fn on_logout(&self, session_id: &SessionId);

    /// Called before an administrative message (Logon, Heartbeat, Logout, …)
    /// is encoded.
    ///
    /// The body is mutable and the mutation is effective: the engine encodes
    /// exactly the message this callback hands back. Fields appended here land
    /// after the ones the session layer wrote, in insertion order. The
    /// canonical use is stamping `Username` (553) and `Password` (554) onto the
    /// outbound Logon.
    ///
    /// The standard header is not visible: it is stamped after this returns,
    /// and `MsgSeqNum` (34) is not decided until the frame exists. A body that
    /// carries a tag the engine stamps itself, or a value with no legal wire
    /// form, is refused — the message is dropped with a warning and the session
    /// continues, having spent no sequence number. See
    /// [`crate::outbound::RESERVED_TAGS`].
    ///
    /// # Arguments
    /// * `message` - The message about to be encoded (mutable)
    /// * `session_id` - The session identifier
    async fn to_admin(&self, message: &mut OutboundMessage, session_id: &SessionId);

    /// Called when an admin message is received.
    ///
    /// # Arguments
    /// * `message` - The received message
    /// * `session_id` - The session identifier
    ///
    /// # Returns
    /// `Ok(())` to accept, `Err(RejectReason)` to reject.
    #[allow(clippy::wrong_self_convention)]
    async fn from_admin(
        &self,
        message: &RawMessage<'_>,
        session_id: &SessionId,
    ) -> Result<(), RejectReason>;

    /// Called before an application message is encoded, through the default
    /// [`Application::to_app_checked`].
    ///
    /// Same contract as [`Application::to_admin`]: the body is mutable, the
    /// mutation is effective, and the header — including `MsgSeqNum` (34) — is
    /// stamped afterwards.
    ///
    /// The engine calls [`Application::to_app_checked`], not this method;
    /// its default runs this one and never refuses the message, so an
    /// implementation that overrides only `to_app` behaves exactly as it did
    /// before `to_app_checked` existed. An implementation that overrides
    /// `to_app_checked` replaces this call: it runs `to_app` itself if it
    /// still wants it.
    ///
    /// # Arguments
    /// * `message` - The message about to be encoded (mutable)
    /// * `session_id` - The session identifier
    async fn to_app(&self, message: &mut OutboundMessage, session_id: &SessionId);

    /// Called before an application message is encoded, with the power to
    /// refuse it: the engine's outbound gate, the equivalent of QuickFIX's
    /// `DoNotSend`.
    ///
    /// The engine calls this for **every new** outbound application message,
    /// whether it was handed in through [`Connection::send`](crate::Connection::send)
    /// or [`Connection::send_tracked`](crate::Connection::send_tracked), so
    /// no new message bypasses it, and awaits the [`SendVerdict`] it returns.
    /// The default runs [`Application::to_app`] and returns `Ok(())`, at the
    /// cost of `to_app`'s own future and nothing more.
    ///
    /// It is not an `async fn`: it returns a [`SendVerdict`], so a gate that
    /// decides at once costs no allocation, and so the default costs a
    /// message no more than `to_app` did (an `async fn` default awaiting
    /// `to_app` would box a second future per message). Build the verdict
    /// with [`SendVerdict::ready`] for a decision taken now, or
    /// [`SendVerdict::new`] for one that must wait:
    ///
    /// ```
    /// use async_trait::async_trait;
    /// use ironfix_core::message::RawMessage;
    /// use ironfix_engine::application::{Application, RejectReason, SendVerdict, SessionId};
    /// use ironfix_engine::OutboundMessage;
    /// use std::sync::atomic::{AtomicBool, Ordering};
    ///
    /// struct Gateway {
    ///     killed: AtomicBool,
    /// }
    ///
    /// #[async_trait]
    /// impl Application for Gateway {
    ///     async fn on_create(&self, _: &SessionId) {}
    ///     async fn on_logon(&self, _: &SessionId) {}
    ///     async fn on_logout(&self, _: &SessionId) {}
    ///     async fn to_admin(&self, _: &mut OutboundMessage, _: &SessionId) {}
    ///     async fn from_admin(&self, _: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
    ///         Ok(())
    ///     }
    ///     async fn to_app(&self, _: &mut OutboundMessage, _: &SessionId) {}
    ///     async fn from_app(&self, _: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
    ///         Ok(())
    ///     }
    ///
    ///     // The kill switch decides at once: no allocation.
    ///     fn to_app_checked<'a>(
    ///         &'a self,
    ///         _message: &'a mut OutboundMessage,
    ///         _session_id: &'a SessionId,
    ///     ) -> SendVerdict<'a> {
    ///         if self.killed.load(Ordering::Acquire) {
    ///             SendVerdict::ready(Err(RejectReason::new(1, "kill switch on")))
    ///         } else {
    ///             SendVerdict::ready(Ok(()))
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// **A replay is not gated.** The answer to a `ResendRequest` (2) and the
    /// resend a `NextExpectedMsgSeqNum` (789) asks for write each filed frame
    /// as it was filed, with `PossDupFlag` (43) = Y, without calling this:
    /// the message already went out under its number. This differs from
    /// QuickFIX, which calls `toApp` on each resent application message and
    /// gap-fills one that throws `DoNotSend`. A gate that must also stop
    /// stale orders from being resent cannot rely on this callback today.
    ///
    /// - A verdict resolving `Ok(())` sends the message as this callback
    ///   leaves it: the body is mutable and the mutation is effective, as for
    ///   `to_app`.
    /// - A verdict resolving `Err(reason)` vetoes it. The veto runs **before**
    ///   a `MsgSeqNum` (34)
    ///   is spent and before the store is touched, so a vetoed message spends
    ///   no number, leaves no hole for the counterparty to resend over, and
    ///   is never filed: the next message takes the number this one would
    ///   have had. The session carries on. A message sent with
    ///   `send_tracked` reports
    ///   [`NotSentReason::Vetoed`](crate::outcome::NotSentReason::Vetoed) with
    ///   `reason`; one sent with `send` has already returned `Ok`, and the
    ///   veto is only logged, at debug level, with the reason's `code`.
    ///
    /// It runs when the message is about to be written, not when it is
    /// queued: a message waiting behind a resend is checked once the resend
    /// is done, so a gate closed meanwhile still stops it.
    ///
    /// Administrative messages never reach it, and nothing can veto them:
    /// Logon, Logout, Heartbeat, TestRequest, ResendRequest, SequenceReset,
    /// Reject and XmlMessage (n) are session-layer messages, the first seven
    /// what keeps the session legal, so they go through
    /// [`Application::to_admin`], which can only mutate them.
    ///
    /// A wrapper that delegates to an inner application must forward this
    /// method too, not only `to_app`: a wrapper that forwards `to_app` alone
    /// inherits the default here, which calls the wrapper's `to_app` and
    /// never the inner `to_app_checked`, so the inner gate is silently
    /// skipped.
    ///
    /// # Arguments
    /// * `message` - The message about to be encoded (mutable)
    /// * `session_id` - The session identifier
    ///
    /// # Verdict
    /// A [`SendVerdict`] resolving `Err(RejectReason)` vetoes the message, as
    /// described above. The reason's `code` and `text` are the application's
    /// own; the engine does not put them on the wire.
    fn to_app_checked<'a>(
        &'a self,
        message: &'a mut OutboundMessage,
        session_id: &'a SessionId,
    ) -> SendVerdict<'a> {
        SendVerdict::forward(self.to_app(message, session_id))
    }

    /// Called when an application message is received.
    ///
    /// # Arguments
    /// * `message` - The received message
    /// * `session_id` - The session identifier
    ///
    /// # Returns
    /// `Ok(())` to accept, `Err(RejectReason)` to reject.
    #[allow(clippy::wrong_self_convention)]
    async fn from_app(
        &self,
        message: &RawMessage<'_>,
        session_id: &SessionId,
    ) -> Result<(), RejectReason>;
}

/// What [`Application::to_app_checked`] decided about one outbound
/// application message: a future the engine awaits, resolving to `Ok(())` to
/// send the message or `Err(RejectReason)` to veto it.
///
/// Build one with [`SendVerdict::ready`] for a decision taken at once, which
/// allocates nothing, or [`SendVerdict::new`] for a decision that must
/// wait (on a risk service, say), which boxes its future once. The default
/// `to_app_checked` wraps the future of [`Application::to_app`] without
/// boxing it again.
#[must_use = "a verdict does nothing unless the engine awaits it"]
pub struct SendVerdict<'a> {
    /// The decision, or the future that produces it.
    inner: Verdict<'a>,
}

/// The forms a [`SendVerdict`] takes.
enum Verdict<'a> {
    /// Decided: taken by the first poll.
    Ready(Option<Result<(), RejectReason>>),
    /// The default: the boxed `to_app` future, after which the message is
    /// sent.
    Forward(Pin<Box<dyn Future<Output = ()> + Send + 'a>>),
    /// A decision that has to wait.
    Pending(Pin<Box<dyn Future<Output = Result<(), RejectReason>> + Send + 'a>>),
}

impl<'a> SendVerdict<'a> {
    /// A verdict decided now: `Ok(())` sends the message, `Err(reason)`
    /// vetoes it. Allocates nothing.
    pub const fn ready(decision: Result<(), RejectReason>) -> Self {
        Self {
            inner: Verdict::Ready(Some(decision)),
        }
    }

    /// A verdict that waits on `decision`, boxed once. The future may still
    /// mutate the message it captured; the engine frames the message once
    /// the future resolves `Ok(())`.
    pub fn new(decision: impl Future<Output = Result<(), RejectReason>> + Send + 'a) -> Self {
        Self {
            inner: Verdict::Pending(Box::pin(decision)),
        }
    }

    /// The default verdict: run `to_app`'s future, then send. It reuses the
    /// box `async_trait` already made for `to_app`.
    pub(crate) fn forward(to_app: Pin<Box<dyn Future<Output = ()> + Send + 'a>>) -> Self {
        Self {
            inner: Verdict::Forward(to_app),
        }
    }
}

impl Future for SendVerdict<'_> {
    type Output = Result<(), RejectReason>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Every form is `Unpin` (a box, or a plain value), so the verdict is.
        match &mut self.get_mut().inner {
            Verdict::Ready(decision) => {
                // A verdict polled again after it resolved sends: the engine
                // never does, and there is nothing else to report.
                Poll::Ready(decision.take().unwrap_or(Ok(())))
            }
            Verdict::Forward(to_app) => to_app.as_mut().poll(cx).map(|()| Ok(())),
            Verdict::Pending(decision) => decision.as_mut().poll(cx),
        }
    }
}

impl std::fmt::Debug for SendVerdict<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let form = match &self.inner {
            Verdict::Ready(Some(Ok(()))) => "ready: send",
            Verdict::Ready(Some(Err(_))) => "ready: veto",
            Verdict::Ready(None) => "taken",
            Verdict::Forward(_) => "running to_app",
            Verdict::Pending(_) => "pending",
        };
        f.debug_struct("SendVerdict").field("form", &form).finish()
    }
}

/// Default no-op application implementation.
#[derive(Debug, Default)]
pub struct NoOpApplication;

#[async_trait]
impl Application for NoOpApplication {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {}

    async fn on_logout(&self, _session_id: &SessionId) {}

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id() {
        let id = SessionId::new("FIX.4.4", "SENDER", "TARGET");
        assert_eq!(id.begin_string, "FIX.4.4");
        assert_eq!(id.sender_comp_id, "SENDER");
        assert_eq!(id.target_comp_id, "TARGET");
        assert_eq!(id.to_string(), "FIX.4.4:SENDER->TARGET");
    }

    #[test]
    fn test_reject_reason() {
        let reason = RejectReason::new(1, "Invalid tag").with_ref_tag(35);
        assert_eq!(reason.code, 1);
        assert_eq!(reason.text, "Invalid tag");
        assert_eq!(reason.ref_tag, Some(35));
    }

    #[tokio::test]
    async fn test_noop_application() {
        let app = NoOpApplication;
        let session_id = SessionId::new("FIX.4.4", "SENDER", "TARGET");

        app.on_create(&session_id).await;
        app.on_logon(&session_id).await;
        app.on_logout(&session_id).await;
    }

    /// An application that overrides `to_app` only, stamping `Account` (1).
    struct StampsAccount;

    #[async_trait]
    impl Application for StampsAccount {
        async fn on_create(&self, _session_id: &SessionId) {}

        async fn on_logon(&self, _session_id: &SessionId) {}

        async fn on_logout(&self, _session_id: &SessionId) {}

        async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

        async fn from_admin(
            &self,
            _message: &RawMessage<'_>,
            _session_id: &SessionId,
        ) -> Result<(), RejectReason> {
            Ok(())
        }

        async fn to_app(&self, message: &mut OutboundMessage, _session_id: &SessionId) {
            message.push_str(1, "ACC-1");
        }

        async fn from_app(
            &self,
            _message: &RawMessage<'_>,
            _session_id: &SessionId,
        ) -> Result<(), RejectReason> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_send_verdict_ready_new_and_forward_resolve_their_decision() {
        assert_eq!(SendVerdict::ready(Ok(())).await, Ok(()));
        let veto = RejectReason::new(3, "limit");
        assert_eq!(
            SendVerdict::ready(Err(veto.clone())).await,
            Err(veto.clone())
        );
        let waited = SendVerdict::new(async move {
            tokio::task::yield_now().await;
            Err(veto)
        });
        assert!(format!("{waited:?}").contains("pending"));
        assert_eq!(waited.await.map_err(|reason| reason.code), Err(3));
        let forwarded = SendVerdict::forward(Box::pin(async {}));
        assert!(format!("{forwarded:?}").contains("to_app"));
        assert_eq!(forwarded.await, Ok(()), "the default sends after to_app");
    }

    #[tokio::test]
    async fn test_default_to_app_checked_runs_to_app_and_never_vetoes() {
        let session_id = SessionId::new("FIX.4.4", "SENDER", "TARGET");
        let mut order = OutboundMessage::new(ironfix_core::message::MsgType::NewOrderSingle);
        order.push_str(11, "ORDER-1");

        let verdict = StampsAccount.to_app_checked(&mut order, &session_id).await;
        assert_eq!(verdict, Ok(()), "the default never vetoes");
        assert_eq!(
            order.get(1),
            Some(&b"ACC-1"[..]),
            "the default runs to_app, whose mutation is kept"
        );

        let mut order = OutboundMessage::new(ironfix_core::message::MsgType::NewOrderSingle);
        assert_eq!(
            NoOpApplication
                .to_app_checked(&mut order, &session_id)
                .await,
            Ok(())
        );
        assert_eq!(
            order.fields().len(),
            0,
            "the no-op application adds nothing"
        );
    }
}
