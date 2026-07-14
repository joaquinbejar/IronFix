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
    /// trailer; the message only needs body fields.
    ///
    /// # Arguments
    /// * `message` - The application message to send
    ///
    /// # Errors
    /// Returns [`EngineError::Closed`] if the session is already closed.
    pub async fn send(&self, message: OutboundMessage) -> Result<(), EngineError> {
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
        self.runtime
            .heartbeat
            .lock()
            .expect("heartbeat lock poisoned")
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
