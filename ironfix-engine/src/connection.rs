/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Live-session connection handle.
//!
//! A [`Connection`] is returned by [`Initiator::connect`](crate::Initiator::connect)
//! once the FIX session is established. It is a cheap-to-clone handle that
//! provides an outbound message sink and close observation; the actual
//! read/write reactor runs in a background task.

use crate::application::SessionId;
use crate::error::EngineError;
use crate::outbound::OutboundMessage;
use ironfix_session::{HeartbeatManager, SequenceManager};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, watch};

/// Commands sent from a [`Connection`] handle to the session reactor.
#[derive(Debug)]
pub(crate) enum Command {
    /// Send an application message.
    Send(OutboundMessage),
    /// Initiate a graceful logout.
    Logout,
}

/// Session runtime state shared between the reactor and connection handles.
#[derive(Debug)]
pub(crate) struct SessionRuntime {
    /// Sender/target sequence counters.
    pub(crate) sequences: SequenceManager,
    /// Heartbeat and TestRequest timing state.
    pub(crate) heartbeat: Mutex<HeartbeatManager>,
}

/// Handle to a live FIX session.
///
/// Cloning is cheap; all clones refer to the same session. The session is
/// closed when the transport drops, the counterparty logs out, a heartbeat
/// timeout is detected, or [`Connection::logout`] completes.
///
/// # Dropping every handle logs out
///
/// The reactor stops when the last clone is dropped: it reads that as "nobody
/// can drive this session any more" and performs a graceful Logout rather than
/// leaving a task holding a socket forever. A consumer that wants the session
/// to outlive its handle must keep one alive — typically by holding it until
/// [`Connection::wait_closed`] returns.
#[derive(Debug, Clone)]
pub struct Connection {
    /// Session identifier.
    pub(crate) session_id: SessionId,
    /// Command channel to the reactor.
    pub(crate) commands: mpsc::Sender<Command>,
    /// Closed-flag observation channel.
    pub(crate) closed: watch::Receiver<bool>,
    /// Shared session runtime state.
    pub(crate) runtime: Arc<SessionRuntime>,
}

impl Connection {
    /// Returns the session identifier.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Sends an application message on the session.
    ///
    /// The engine stamps the standard header (including MsgSeqNum) and
    /// trailer; the message only needs body fields. It is checked here, before
    /// it is queued, so a message the session layer will not carry is refused
    /// to the caller rather than dropped later.
    ///
    /// # Arguments
    /// * `message` - The application message to send
    ///
    /// # Errors
    /// * [`EngineError::ReservedMsgType`] for an administrative MsgType.
    ///   Logon, Logout, SequenceReset and the rest belong to the session state
    ///   machine; one sent here would bypass the typestate and the engine's
    ///   phase tracking — a Logout sent this way never arms the logout timeout.
    /// * [`EngineError::ReservedTag`] for a body field that repeats a tag the
    ///   engine stamps itself (see [`crate::outbound::RESERVED_TAGS`]), which
    ///   would put two occurrences of it in the frame.
    /// * [`EngineError::InvalidField`] for a value with no legal wire form.
    /// * [`EngineError::Closed`] if the session is already closed.
    ///
    /// # Accepted is not sent
    ///
    /// `Ok` means the message was queued for the reactor, not that it reached
    /// the counterparty. A message queued while a Logout is already pending is
    /// dropped with a warning — the session is on its way out and a new
    /// application message would arrive after the Logout the counterparty has
    /// already seen. Use [`Connection::wait_closed`] to observe the end of the
    /// session and `next_sender_seq` to observe progress.
    pub async fn send(&self, message: OutboundMessage) -> Result<(), EngineError> {
        crate::outbound::check_sendable(&message)?;
        self.commands
            .send(Command::Send(message))
            .await
            .map_err(|_| EngineError::Closed)
    }

    /// Initiates a graceful logout.
    ///
    /// A Logout message is sent to the counterparty; the session closes when
    /// the Logout acknowledgement arrives or the logout timeout elapses.
    /// Use [`Connection::wait_closed`] to observe completion.
    ///
    /// # Errors
    /// Returns [`EngineError::Closed`] if the session is already closed.
    pub async fn logout(&self) -> Result<(), EngineError> {
        self.commands
            .send(Command::Logout)
            .await
            .map_err(|_| EngineError::Closed)
    }

    /// Waits until the session is closed.
    ///
    /// Fires on transport drop, counterparty logout, heartbeat timeout, or
    /// completion of a locally initiated logout. Returns immediately if the
    /// session is already closed.
    ///
    /// It fires **after** the inbound application messages already queued have
    /// been through `from_app` and `on_logout` has run, so a handler still in
    /// flight when the session ends delays this by however long it takes to
    /// finish, up to an internal drain bound.
    pub async fn wait_closed(&self) {
        let mut closed = self.closed.clone();
        // An error means the reactor is gone, which also means closed.
        let _ = closed.wait_for(|closed| *closed).await;
    }

    /// Returns true if the session is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.has_changed().is_err() || *self.closed.borrow()
    }

    /// Returns true if the session has detected a heartbeat timeout
    /// (a TestRequest went unanswered for a full heartbeat interval).
    #[must_use]
    pub fn is_timed_out(&self) -> bool {
        // A poisoned lock means a previous holder panicked. The heartbeat state
        // is plain timestamps with no invariant a panic could leave
        // half-applied, so the guard is recovered rather than propagated:
        // taking the consumer's process down over a heartbeat timestamp — and
        // under `panic = "abort"` that is what propagating means — is never the
        // right trade.
        self.runtime
            .heartbeat
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_timed_out()
    }

    /// Returns the next outgoing (sender) sequence number.
    #[must_use]
    pub fn next_sender_seq(&self) -> u64 {
        self.runtime.sequences.next_sender_seq().value()
    }

    /// Returns the next expected incoming (target) sequence number.
    #[must_use]
    pub fn next_target_seq(&self) -> u64 {
        self.runtime.sequences.next_target_seq().value()
    }
}
