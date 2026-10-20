/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! The synchronous application callbacks, for the sans-IO path.
//!
//! [`SyncApplication`] is [`Application`] with every callback synchronous:
//! the same method set, the same defaults and the same contract (when each
//! callback runs, what a rejection or a veto does, what is mutable). A
//! driver that runs sessions on its own event loop, with no async runtime
//! (ADR-0002, issue #92), calls it directly, and no callback allocates a
//! future.
//!
//! [`SyncApplicationAdapter`] makes a synchronous application usable where
//! an [`Application`] is expected, such as under this crate's Tokio engines.
//! Each async callback runs the synchronous one inline, so a callback that
//! blocks blocks the runtime thread and, for the callbacks the session
//! reactor awaits inline (`from_admin`, `to_admin`, the send gates), the
//! session itself: the adapter is sound for callbacks that decide from state
//! they already hold, and not for one that waits on a disk, a network or a
//! lock held across a slow operation. The gates go through
//! [`SendVerdict::ready`], so a vetoing or allowing decision allocates
//! nothing beyond what `async_trait` boxes for the other callbacks.

use crate::application::{
    Application, RejectReason, SendVerdict, SessionId, log_inbound_lost, log_sequence_mismatch,
};
use crate::close::CloseReason;
use crate::loss::InboundLoss;
use crate::mismatch::SequenceMismatch;
use crate::outbound::OutboundMessage;
use crate::tls::PeerInfo;
use async_trait::async_trait;
use ironfix_core::message::RawMessage;

/// [`Application`] with synchronous callbacks, for a driver without an async
/// runtime.
///
/// Every method has the meaning and the default of the [`Application`]
/// method of the same name.
pub trait SyncApplication: Send + Sync {
    /// See [`Application::on_create`].
    fn on_create(&self, session_id: &SessionId);

    /// See [`Application::authorize_peer`]. The default accepts every peer.
    ///
    /// # Errors
    /// A `RejectReason` refuses the peer.
    fn authorize_peer(&self, session_id: &SessionId, peer: &PeerInfo) -> Result<(), RejectReason> {
        let _ = (session_id, peer);
        Ok(())
    }

    /// See [`Application::on_logon`].
    fn on_logon(&self, session_id: &SessionId);

    /// See [`Application::on_logout`].
    fn on_logout(&self, session_id: &SessionId);

    /// See [`Application::on_session_closed`]. The default forwards to
    /// [`SyncApplication::on_logout`] when the session had reached Active.
    fn on_session_closed(&self, session_id: &SessionId, reason: &CloseReason) {
        if reason.was_active() {
            self.on_logout(session_id);
        }
    }

    /// See [`Application::on_inbound_lost`]. The default logs the span at
    /// error level, numbers only.
    fn on_inbound_lost(&self, session_id: &SessionId, loss: &InboundLoss) {
        log_inbound_lost(session_id, loss);
    }

    /// See [`Application::on_sequence_mismatch`]. The default logs the
    /// numbers at warn level.
    fn on_sequence_mismatch(&self, session_id: &SessionId, mismatch: &SequenceMismatch) {
        log_sequence_mismatch(session_id, mismatch);
    }

    /// See [`Application::to_admin`].
    fn to_admin(&self, message: &mut OutboundMessage, session_id: &SessionId);

    /// See [`Application::from_admin`].
    ///
    /// # Errors
    /// A `RejectReason` rejects the message.
    #[allow(clippy::wrong_self_convention)]
    fn from_admin(
        &self,
        message: &RawMessage<'_>,
        session_id: &SessionId,
    ) -> Result<(), RejectReason>;

    /// See [`Application::to_app`].
    fn to_app(&self, message: &mut OutboundMessage, session_id: &SessionId);

    /// See [`Application::to_app_checked`]: the outbound gate. The default
    /// runs [`SyncApplication::to_app`] and never vetoes. A wrapper that
    /// delegates to an inner application must forward this method too.
    ///
    /// # Errors
    /// A `RejectReason` vetoes the message before a `MsgSeqNum` (34) is
    /// spent.
    fn to_app_checked(
        &self,
        message: &mut OutboundMessage,
        session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        self.to_app(message, session_id);
        Ok(())
    }

    /// See [`Application::to_app_resend`]: the replay gate. The default
    /// allows every replay.
    ///
    /// # Errors
    /// A `RejectReason` gap-fills the message instead of resending it.
    fn to_app_resend(
        &self,
        message: &RawMessage<'_>,
        session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        let _ = (message, session_id);
        Ok(())
    }

    /// See [`Application::from_app`].
    ///
    /// # Errors
    /// A `RejectReason` rejects the message.
    #[allow(clippy::wrong_self_convention)]
    fn from_app(
        &self,
        message: &RawMessage<'_>,
        session_id: &SessionId,
    ) -> Result<(), RejectReason>;
}

/// A [`SyncApplication`] used as an [`Application`].
///
/// Every async callback runs the synchronous one of the same name inline;
/// see the [module docs](self) for when that is sound.
#[derive(Debug, Clone, Default)]
pub struct SyncApplicationAdapter<T> {
    /// The synchronous application.
    inner: T,
}

impl<T> SyncApplicationAdapter<T> {
    /// Wraps `inner`.
    #[must_use]
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }

    /// The synchronous application.
    #[must_use]
    pub const fn inner(&self) -> &T {
        &self.inner
    }

    /// Unwraps the synchronous application.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

#[async_trait]
impl<T: SyncApplication> Application for SyncApplicationAdapter<T> {
    async fn on_create(&self, session_id: &SessionId) {
        self.inner.on_create(session_id);
    }

    async fn authorize_peer(
        &self,
        session_id: &SessionId,
        peer: &PeerInfo,
    ) -> Result<(), RejectReason> {
        self.inner.authorize_peer(session_id, peer)
    }

    async fn on_logon(&self, session_id: &SessionId) {
        self.inner.on_logon(session_id);
    }

    async fn on_logout(&self, session_id: &SessionId) {
        self.inner.on_logout(session_id);
    }

    async fn on_session_closed(&self, session_id: &SessionId, reason: &CloseReason) {
        self.inner.on_session_closed(session_id, reason);
    }

    async fn on_inbound_lost(&self, session_id: &SessionId, loss: &InboundLoss) {
        self.inner.on_inbound_lost(session_id, loss);
    }

    async fn on_sequence_mismatch(&self, session_id: &SessionId, mismatch: &SequenceMismatch) {
        self.inner.on_sequence_mismatch(session_id, mismatch);
    }

    async fn to_admin(&self, message: &mut OutboundMessage, session_id: &SessionId) {
        self.inner.to_admin(message, session_id);
    }

    async fn from_admin(
        &self,
        message: &RawMessage<'_>,
        session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        self.inner.from_admin(message, session_id)
    }

    async fn to_app(&self, message: &mut OutboundMessage, session_id: &SessionId) {
        self.inner.to_app(message, session_id);
    }

    fn to_app_checked<'a>(
        &'a self,
        message: &'a mut OutboundMessage,
        session_id: &'a SessionId,
    ) -> SendVerdict<'a> {
        SendVerdict::ready(self.inner.to_app_checked(message, session_id))
    }

    fn to_app_resend<'a>(
        &'a self,
        message: &'a RawMessage<'_>,
        session_id: &'a SessionId,
    ) -> SendVerdict<'a> {
        SendVerdict::ready(self.inner.to_app_resend(message, session_id))
    }

    async fn from_app(
        &self,
        message: &RawMessage<'_>,
        session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        self.inner.from_app(message, session_id)
    }
}
