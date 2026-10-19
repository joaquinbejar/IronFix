/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Application callback interface.
//!
//! This module defines the callback interface for handling FIX messages,
//! following the QuickFIX pattern with async support.

use crate::close::CloseReason;
use crate::loss::InboundLoss;
use crate::outbound::OutboundMessage;
use crate::tls::PeerInfo;
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
/// [`Application::to_app_resend`] runs inline too, on each filed application
/// frame a resend is about to replay, because its verdict decides whether
/// that number is resent or gap-filled. While it is pending the session
/// pauses entirely, as for any inline callback.
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

    /// Called when the transport has proved who the counterparty is, before
    /// any FIX message is exchanged with it.
    ///
    /// Runs on the TLS entry points
    /// (`Initiator::connect_tls`,
    /// `Acceptor::serve_tls`,
    /// `AcceptorRegistry::serve_tls`,
    /// with the `tls` feature) once the TLS handshake has completed, and on
    /// the `*_with_peer` stream entry points, after
    /// [`Application::on_create`]. It never runs on a plain TCP or stream
    /// session. `peer` carries the certificates the counterparty presented,
    /// end-entity first, so an application can bind a client certificate to
    /// the session it claims, for instance by requiring that it names the
    /// session's `TargetCompID`.
    ///
    /// Bind to [`PeerInfo::end_entity_certificate`] only: it is the one
    /// certificate the TLS layer verified against the configured roots. The
    /// rest of the chain is metadata the peer chose to send, which may hold
    /// unrelated certificates nobody verified; an entry after the first
    /// proves neither a verified issuer nor an identity.
    ///
    /// The initiator calls it before its Logon, which may carry `Password`
    /// (554), is written; the acceptor before the inbound Logon is read (for
    /// an [`AcceptorRegistry`](crate::AcceptorRegistry), once the Logon has
    /// been routed to `session_id`, before it is checked). An `Err` closes the
    /// connection without writing anything to it, no store is touched, and
    /// the caller gets [`EngineError::Tls`](crate::EngineError::Tls) carrying
    /// [`TlsError::PeerRejected`](crate::TlsError::PeerRejected) with the
    /// reason's `text`; [`Application::on_session_closed`] gets
    /// [`CloseReason::Tls`]. The reason's `code` and `ref_tag` are not used.
    ///
    /// The default accepts every peer the TLS layer accepted.
    ///
    /// # Arguments
    /// * `session_id` - The session the connection is for
    /// * `peer` - What the transport proved about the counterparty
    async fn authorize_peer(
        &self,
        _session_id: &SessionId,
        _peer: &PeerInfo,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    /// Called on successful logon.
    ///
    /// # Arguments
    /// * `session_id` - The session identifier
    async fn on_logon(&self, session_id: &SessionId);

    /// Called on logout.
    ///
    /// Called once for every session that reached Active, whatever ended it,
    /// through the default [`Application::on_session_closed`]. Override that
    /// method to learn why the session ended.
    ///
    /// # Arguments
    /// * `session_id` - The session identifier
    async fn on_logout(&self, session_id: &SessionId);

    /// Called once when a session ends, with the reason it ended.
    ///
    /// The engine calls this, not [`Application::on_logout`], on every close
    /// path: after the reactor of a session that reached Active has drained
    /// the application queue (before
    /// [`Connection::wait_closed`](crate::Connection::wait_closed) returns),
    /// and also when a Logon handshake fails after
    /// [`Application::on_create`] has run, with
    /// [`CloseReason::LogonFailed`] (or [`CloseReason::ConnectFailed`] when
    /// the dial itself fails). A handshake whose future the caller drops
    /// before it completes gets no call: nothing can run asynchronously
    /// from a drop.
    ///
    /// The default forwards to [`Application::on_logout`] when the session
    /// had reached Active ([`CloseReason::was_active`]), which is exactly
    /// when `on_logout` was called before this method existed, so an
    /// implementation that does not override it sees no change. An override
    /// replaces that call: it runs `on_logout` itself if it still wants it.
    ///
    /// The reason never carries a frame or any credential; see
    /// [`crate::close`].
    ///
    /// # Arguments
    /// * `session_id` - The session identifier
    /// * `reason` - Why the session ended
    async fn on_session_closed(&self, session_id: &SessionId, reason: &CloseReason) {
        if reason.was_active() {
            self.on_logout(session_id).await;
        }
    }

    /// Called when inbound messages may not have reached
    /// [`Application::from_app`], with the `MsgSeqNum` span (issue #105,
    /// ADR-0030).
    ///
    /// Inbound application delivery is at most once: a message is accepted,
    /// and its number persisted, before `from_app` sees it, and the engine
    /// does not redeliver it. It reports what it cannot vouch for instead:
    ///
    /// - at the start of a session with a store attached, before the Logon
    ///   is sent (initiator) or acknowledged (acceptor), the span the
    ///   previous session accepted above the store's application watermark
    ///   ([`InboundLossCause::FoundAtStart`](crate::InboundLossCause::FoundAtStart));
    /// - at the close of a session whose application dispatcher was aborted
    ///   after its drain timeout, or stopped after a failed watermark write,
    ///   before [`Application::on_session_closed`]
    ///   ([`InboundLossCause::DispatcherStopped`](crate::InboundLossCause::DispatcherStopped)).
    ///
    /// The engine records the span as reported only after this returns, by
    /// persisting the watermark up to its end: a crash before that write
    /// lands reports it again at the next start. A span reported at close
    /// is not reported again at the next start **once that write has
    /// succeeded**; if it fails (logged), the next start reports it again.
    /// Without a store nothing is persisted and no start report is made.
    ///
    /// The span can include administrative messages and messages whose
    /// `from_app` had returned just before a crash; see [`crate::loss`]. To
    /// recover the content, ask the counterparty for the span out of band,
    /// or reconcile with it (an order status request, for instance): a
    /// `ResendRequest` for numbers already accepted is not part of this
    /// engine's session behaviour.
    ///
    /// The default logs the span at error level, numbers only.
    ///
    /// # Arguments
    /// * `session_id` - The session identifier
    /// * `loss` - The span, and when it was found
    async fn on_inbound_lost(&self, session_id: &SessionId, loss: &InboundLoss) {
        tracing::error!(
            session = %session_id,
            first = loss.first(),
            last = loss.last(),
            cause = %loss.cause(),
            "inbound messages in MsgSeqNum range first..=last were accepted but may not have \
             reached from_app; they are not redelivered"
        );
    }

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
    /// **A replay does not come here.** The answer to a `ResendRequest` (2)
    /// and the resend a `NextExpectedMsgSeqNum` (789) asks for go through
    /// [`Application::to_app_resend`] instead, which sees the rebuilt frame
    /// read-only and can veto it, so it is gap-filled rather than resent.
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

    /// Called before a filed application message is **resent**, with the
    /// power to refuse it: the replay gate, the equivalent of QuickFIX
    /// calling `toApp` on a resent message and gap-filling it on
    /// `DoNotSend` (ADR-0023, "Replay gate").
    ///
    /// The engine calls this for each stored application message it is
    /// about to replay, both in the answer to a `ResendRequest` (2) and in
    /// the resend a `NextExpectedMsgSeqNum` (789) on Logon asks for.
    /// `message` is the frame exactly as it will go on the wire: the filed
    /// body under its original `MsgSeqNum` (34), with `PossDupFlag` (43) = Y,
    /// a fresh `SendingTime` (52) and `OrigSendingTime` (122). It is
    /// read-only: a replay must say what was first sent under its number.
    ///
    /// - A verdict resolving `Ok(())` resends the message unchanged.
    /// - A verdict resolving `Err(reason)` gap-fills it: its number is
    ///   covered by a SequenceReset-GapFill (123 = Y) instead. Consecutive
    ///   vetoed messages, together with any administrative messages and
    ///   holes next to them, are covered by **one** gap fill, which runs up
    ///   to the next message that is resent or to the end of the range. The
    ///   veto is logged at debug level with the sequence number and the
    ///   reason's `code` only.
    ///
    /// The default allows every replay, so an implementor that does not
    /// override this sees every filed application message resent as filed.
    /// [`Application::to_app_checked`] is never called for a replay, and
    /// administrative messages never reach this method: they are gap-filled
    /// on a resend whatever it would say.
    ///
    /// **The session waits with it.** The verdict is awaited inline by the
    /// session reactor, as [`SendVerdict::new`] documents for every inline
    /// gate: while it is pending the session reads nothing from the socket
    /// (a counterparty's Logout included), flushes nothing it has buffered
    /// (earlier replays included), runs none of its timers, and answers no
    /// Heartbeat or TestRequest, so a slow decision can time the session
    /// out. Every new message also stays held behind the resend. Build the
    /// verdict with [`SendVerdict::ready`] when the decision can be taken at
    /// once, and bound any decision that must wait.
    ///
    /// A wrapper that delegates to an inner application must forward this
    /// method too, or the inner gate is skipped for replays.
    ///
    /// # Arguments
    /// * `message` - The rebuilt replay frame (read-only)
    /// * `session_id` - The session identifier
    fn to_app_resend<'a>(
        &'a self,
        message: &'a RawMessage<'_>,
        session_id: &'a SessionId,
    ) -> SendVerdict<'a> {
        let _ = (message, session_id);
        SendVerdict::ready(Ok(()))
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
/// wait (on a risk service, say), which boxes its future once and holds the
/// session up while it waits. The default `to_app_checked` wraps the future
/// of [`Application::to_app`] without boxing it again.
///
/// Like any future it is polled until it resolves, once. A verdict polled
/// again after it resolved vetoes, with `RejectReason` code 0 and text
/// "verdict already consumed", rather than sending: it no longer decides
/// about any message. The engine never polls one again.
#[must_use = "a verdict does nothing unless the engine awaits it"]
pub struct SendVerdict<'a> {
    /// The decision, or the future that produces it.
    inner: Verdict<'a>,
}

/// The `Text` of the veto a [`SendVerdict`] returns when it is polled again
/// after it resolved.
const CONSUMED: &str = "verdict already consumed";

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
    ///
    /// **The session waits with it.** The verdict is awaited inline by the
    /// session reactor: while it is pending the session reads nothing,
    /// flushes nothing, and answers no Heartbeat or TestRequest, so a slow
    /// decision can time the session out. A pre-trade risk check or a kill
    /// switch should decide from state it already holds, with
    /// [`SendVerdict::ready`]; reserve `new` for a decision that genuinely
    /// has to wait, and bound it.
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
            // A verdict polled again after it resolved vetoes: it no
            // longer decides about any message, and the safe answer for a
            // gate is not to send. The engine never polls one again.
            Verdict::Ready(decision) => Poll::Ready(
                decision
                    .take()
                    .unwrap_or_else(|| Err(RejectReason::new(0, CONSUMED))),
            ),
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

    #[test]
    fn test_send_verdict_polled_again_after_it_resolved_vetoes() {
        let mut verdict = SendVerdict::ready(Ok(()));
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert_eq!(
            Pin::new(&mut verdict).poll(&mut cx),
            Poll::Ready(Ok(())),
            "the first poll takes the decision"
        );
        match Pin::new(&mut verdict).poll(&mut cx) {
            Poll::Ready(Err(reason)) => {
                assert_eq!(reason.code, 0);
                assert_eq!(reason.text, CONSUMED);
            }
            other => panic!("a repolled verdict must veto, not send: {other:?}"),
        }
        assert!(format!("{verdict:?}").contains("taken"));
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

    #[tokio::test]
    async fn test_default_to_app_resend_allows_every_replay() {
        let session_id = SessionId::new("FIX.4.4", "SENDER", "TARGET");
        let frame = b"8=FIX.4.4\x019=5\x0135=8\x0110=000\x01";
        let raw = match ironfix_tagvalue::Decoder::new(frame)
            .with_checksum_validation(false)
            .decode()
        {
            Ok(raw) => raw,
            Err(err) => panic!("fixture must decode: {err:?}"),
        };
        assert_eq!(
            StampsAccount.to_app_resend(&raw, &session_id).await,
            Ok(()),
            "an override of to_app alone does not gate replays"
        );
        assert_eq!(
            NoOpApplication.to_app_resend(&raw, &session_id).await,
            Ok(())
        );
    }
}
