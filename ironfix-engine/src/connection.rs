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
use ironfix_core::version::FixVersion;
use ironfix_session::{HeartbeatManager, SequenceManager};
use std::sync::{Arc, Mutex, OnceLock};
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
    /// The default application version the counterparty declared in
    /// `DefaultApplVerID` (1137) on its Logon, once the handshake has
    /// checked it; unset on a FIX 4.x session and when it declared none.
    /// Set at most once, during the handshake, and read-only afterwards.
    pub(crate) counterparty_default_appl_version: OnceLock<FixVersion>,
}

impl SessionRuntime {
    /// Builds the runtime of a session about to run its handshake.
    #[must_use]
    pub(crate) fn new(sequences: SequenceManager, heartbeat: HeartbeatManager) -> Self {
        Self {
            sequences,
            heartbeat: Mutex::new(heartbeat),
            counterparty_default_appl_version: OnceLock::new(),
        }
    }

    /// Records the default application version the counterparty declared,
    /// once the handshake has accepted it. A second call is ignored: the
    /// Logon exchange declares it once.
    pub(crate) fn record_counterparty_default_appl_version(&self, version: FixVersion) {
        let _ = self.counterparty_default_appl_version.set(version);
    }
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
    ///
    /// # When `send` waits
    ///
    /// `send` returns as soon as the message is in the outbound queue
    /// (`with_outbound_capacity` on the `Initiator` or `Acceptor`, default
    /// 1024 messages); it waits only while that queue is full. The session
    /// takes messages from the queue in order, and stops taking them in two
    /// cases, so the queue can fill:
    ///
    /// - **While the session is resending** what the counterparty missed (an
    ///   answer to its `ResendRequest`, or the resend its
    ///   `NextExpectedMsgSeqNum` (789) asked for). A message that takes a new
    ///   `MsgSeqNum` must not reach the counterparty in the middle of the
    ///   resend, so queued messages wait behind it, then go out in order,
    ///   after the resend and the session's own replies held behind it. Once
    ///   the queue is full, `send` waits for the whole resend, which may last
    ///   as long as the counterparty takes to read it.
    /// - **While the counterparty reads more slowly than the session
    ///   writes.** Output waiting for the socket stops being added to at
    ///   64 KiB, so `send` is held back by the counterparty's reading rather
    ///   than the waiting output growing. Output that makes no progress at
    ///   all for the write timeout closes the session, and `send` then
    ///   returns [`EngineError::Closed`].
    ///
    /// A caller that must not wait can bound the call with
    /// `tokio::time::timeout`; a message whose `send` was abandoned that way
    /// was not queued.
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
    /// The logout request travels through the same queue as
    /// [`Connection::send`], behind the messages already queued, and waits
    /// as they do (see "When `send` waits"). While the session is resending
    /// what the counterparty missed, the Logout waits behind the resend: FIX
    /// lets the counterparty fill its gap first, so the Logout goes out once
    /// the resend and the messages held behind it are written, and the logout
    /// timeout starts then, not when this method was called. A resend can
    /// therefore delay the close by as long as the counterparty takes to read
    /// it; output that makes no progress for the write timeout still closes
    /// the session.
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

    /// Returns the default application version the counterparty declared in
    /// `DefaultApplVerID` (1137) on its Logon, on a FIX 5.0 session (framed
    /// as FIXT.1.1).
    ///
    /// It is the application version of every inbound application message
    /// that carries no `ApplVerID` (1128); a message with 1128 is in the
    /// version 1128 names. The handshake checked it against
    /// [`SessionConfig::accepts_appl_version`](ironfix_session::SessionConfig::accepts_appl_version),
    /// so it is always a version this session accepts, possibly another than
    /// its own when [`SessionConfig::allowed_appl_versions`](ironfix_session::SessionConfig::allowed_appl_versions)
    /// is set.
    ///
    /// `None` on a FIX 4.x session, which carries no 1137, and on an
    /// initiator whose Logon acknowledgement declared none (accepted unless
    /// [`SessionConfig::require_ack_default_appl_ver_id`](ironfix_session::SessionConfig::require_ack_default_appl_ver_id)
    /// is set): the counterparty's messages without 1128 are then taken to be
    /// in this session's own configured version. On an acceptor it is never
    /// `None` for a FIX 5.0 session, since the Logon must declare it.
    #[must_use]
    pub fn counterparty_default_appl_version(&self) -> Option<FixVersion> {
        self.runtime
            .counterparty_default_appl_version
            .get()
            .copied()
    }
}
