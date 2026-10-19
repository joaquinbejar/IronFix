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
use crate::outcome::{NotSentReason, Receipt, SendOutcome};
use ironfix_core::version::FixVersion;
use ironfix_session::{HeartbeatManager, SequenceManager};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::{mpsc, watch};

/// Commands sent from a [`Connection`] handle to the session reactor.
#[derive(Debug)]
pub(crate) enum Command {
    /// Send an application message.
    Send {
        /// The message.
        message: OutboundMessage,
        /// Where its outcome goes: set by [`Connection::send_tracked`] only,
        /// so a plain [`Connection::send`] allocates nothing for it.
        receipt: Option<Receipt>,
    },
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
    /// Inbound application messages the reactor has accepted in sequence and
    /// handed to the application. Written by the reactor alone.
    inbound_app_messages: AtomicU64,
}

impl SessionRuntime {
    /// Builds the runtime of a session about to run its handshake.
    #[must_use]
    pub(crate) fn new(sequences: SequenceManager, heartbeat: HeartbeatManager) -> Self {
        Self {
            sequences,
            heartbeat: Mutex::new(heartbeat),
            counterparty_default_appl_version: OnceLock::new(),
            inbound_app_messages: AtomicU64::new(0),
        }
    }

    /// Counts one more inbound application message handed to the
    /// application. Only the reactor calls this, so a load and a store
    /// suffice; at `u64::MAX` the count stops moving rather than wrapping.
    pub(crate) fn record_inbound_app_message(&self) {
        let count = self.inbound_app_messages.load(Ordering::Relaxed);
        if let Some(next) = count.checked_add(1) {
            self.inbound_app_messages.store(next, Ordering::Relaxed);
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
    /// When the reactor reaches it, the message goes through
    /// [`Application::to_app_checked`](crate::Application::to_app_checked),
    /// whose default runs `to_app` and never refuses: an application that
    /// overrides only `to_app` sees no change. One that overrides
    /// `to_app_checked` can veto the message there; it is then dropped with a
    /// debug log, having spent no `MsgSeqNum`. Use
    /// [`Connection::send_tracked`] to learn what became of each message.
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
    /// session, and [`Connection::next_sender_seq`] to observe what the
    /// session has committed to send (which counts frames still waiting to
    /// be written).
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
    ///   writes.** A message is written through as soon as it is framed when
    ///   the stream takes it; output that has to wait for the stream stops
    ///   being added to at 16 KiB, so `send` is held back by the
    ///   counterparty's reading rather than the waiting output growing.
    ///   Output the stream accepts none of for the write timeout closes the
    ///   session, and `send` then returns [`EngineError::Closed`].
    ///
    /// A caller that must not wait can bound the call with
    /// `tokio::time::timeout`; a message whose `send` was abandoned that way
    /// was not queued.
    ///
    /// # With an outbound throttle
    ///
    /// With a [`ThrottleConfig`](crate::ThrottleConfig) attached, the session
    /// goes on taking messages from the queue while it holds them back to
    /// their budget's rate (see [`crate::throttle`]): a message its budget
    /// cannot take now is held, in order, or refused, by the budget's
    /// policy, so the queue does not fill because of the throttle. A refused
    /// plain `send` is dropped with a warning (counted per budget), having
    /// spent no `MsgSeqNum`; [`Connection::send_tracked`] reports it as
    /// [`NotSentReason::Throttled`], so prefer `send_tracked` whenever a
    /// throttle is attached. A Logout, whether asked for with
    /// [`Connection::logout`] or caused by dropping every handle, goes out
    /// at once, and the messages still held by the throttle are discarded
    /// rather than written after it.
    pub async fn send(&self, message: OutboundMessage) -> Result<(), EngineError> {
        crate::outbound::check_sendable(&message)?;
        self.commands
            .send(Command::Send {
                message,
                receipt: None,
            })
            .await
            .map_err(|_| EngineError::Closed)
    }

    /// Sends an application message on the session and reports what became
    /// of it.
    ///
    /// The message takes the same path as one handed to [`Connection::send`]:
    /// the same checks before it is queued, the same queue, the same
    /// [`Application::to_app_checked`](crate::Application::to_app_checked)
    /// gate, the same store order and the same wait behind a resend. Instead
    /// of returning once it is queued, this waits for its fate (see
    /// [`crate::outcome`]):
    ///
    /// - [`SendOutcome::Sent`] once the frame has been through the store step
    ///   and a flush that covers it has completed (the session writes through
    ///   a buffer, so that may be after later frames were buffered), with the
    ///   `MsgSeqNum` (34) and
    ///   `SendingTime` (52) the counterparty reads, and `filed`, which says
    ///   whether the store accepted the frame (false without a store, and
    ///   under [`StoreFailurePolicy::Continue`](crate::StoreFailurePolicy::Continue)
    ///   after a failed filing: such a frame is gap-filled, not replayed);
    /// - [`SendOutcome::NotSent`] when no byte of it reached the stream and no
    ///   number was spent: the reason is
    ///   [`NotSentReason::Invalid`] for a message `send` would refuse with an
    ///   error (an administrative MsgType, a reserved tag, a value with no
    ///   wire form) or one `to_app_checked` left that way,
    ///   [`NotSentReason::Vetoed`] when `to_app_checked` refused it,
    ///   [`NotSentReason::StoreRefused`] when the store refused it under
    ///   [`StoreFailurePolicy::CloseSession`](crate::StoreFailurePolicy::CloseSession),
    ///   [`NotSentReason::SequenceExhausted`],
    ///   [`NotSentReason::Throttled`] when the session's outbound throttle
    ///   refused it (see [`crate::throttle`]), and, when the session ends
    ///   first, [`NotSentReason::SessionClosed`],
    ///   [`NotSentReason::LogoutPending`], [`NotSentReason::Discarded`],
    ///   [`NotSentReason::DiscardedBehindResend`] or
    ///   [`NotSentReason::DiscardedByThrottle`];
    /// - [`SendOutcome::Unknown`] when the frame was numbered (being filed,
    ///   or waiting in the write buffer) and the session ended before a flush
    ///   covering it completed: a number is spent when the frame is
    ///   buffered, so this is never `NotSent`. **The
    ///   order may be live**: do not resubmit it blindly. Reconcile it by
    ///   `ClOrdID` (11) after the next Logon, through the `ExecutionReport`
    ///   (8) or an `OrderStatusRequest` (H); a resubmission reuses the
    ///   `ClOrdID` and sets `PossResend` (97) = Y. The number stays spent; the
    ///   frame is replayed under it only if it was filed, no reset erased it
    ///   (at the close, or by `ResetSeqNumFlag` (141) on the next Logon), the
    ///   store still holds it, and the counterparty asks (see
    ///   [`crate::outcome`]).
    ///
    /// It never waits forever: every message queued on a session that ends
    /// resolves, at the latest as the session closes, before
    /// [`Connection::wait_closed`] returns; and once the session has closed
    /// this returns whatever has resolved by then, or
    /// [`NotSentReason::Discarded`].
    ///
    /// # Cost and cancellation
    ///
    /// Each call allocates one single-use channel for its outcome; a plain
    /// `send` allocates none. Dropping the returned future does not withdraw
    /// a message already queued: it is still written, and its outcome is
    /// discarded. Polling several calls concurrently keeps several messages
    /// in flight; each is queued when its future is first polled, in that
    /// order while the queue has room.
    #[must_use = "the outcome says whether the message reached the counterparty; an Unknown one \
                  may be live and must be reconciled"]
    pub async fn send_tracked(&self, message: OutboundMessage) -> SendOutcome {
        if let Err(err) = crate::outbound::check_sendable(&message) {
            return SendOutcome::not_sent(NotSentReason::invalid(&err));
        }
        let (receipt, mut outcome) = Receipt::new();
        let command = Command::Send {
            message,
            receipt: Some(receipt),
        };
        if self.commands.send(command).await.is_err() {
            return SendOutcome::not_sent(NotSentReason::SessionClosed {});
        }
        // Every receipt answers, explicitly or as it is dropped, before the
        // session reports itself closed. Waiting on the close as well means a
        // reactor gone in a way that answered neither cannot leave this
        // waiting: once closed, whatever has arrived is taken, without
        // blocking, and anything else is reported discarded.
        tokio::select! {
            biased;
            resolved = &mut outcome => {
                resolved.unwrap_or(SendOutcome::not_sent(NotSentReason::Discarded {}))
            }
            () = self.wait_closed() => outcome
                .try_recv()
                .unwrap_or(SendOutcome::not_sent(NotSentReason::Discarded {})),
        }
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
    /// lets the counterparty fill its gap first, so the Logout is framed once
    /// the resend and the messages held behind it are. The logout timeout
    /// starts once the Logout has been written whole to the stream, not when
    /// this method was called nor when it was framed behind output the
    /// counterparty had not taken yet; until then no new application message
    /// is sent. A resend, or a counterparty that reads slowly, can therefore
    /// delay the close by as long as the counterparty takes to read; output
    /// the stream accepts none of for the write timeout still closes the
    /// session, and such a close, whose Logout never got out, is not
    /// graceful (`reset_on_logout` does not reset).
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
    ///
    /// A number is spent when its frame is framed and filed, before it is
    /// written: the numbers below this one include frames still waiting in
    /// the session's write buffer for the stream to accept them, and a frame
    /// accepted by the stream has still not necessarily reached the
    /// counterparty. It counts what the session has committed to send, not
    /// what was delivered.
    #[must_use]
    pub fn next_sender_seq(&self) -> u64 {
        self.runtime.sequences.next_sender_seq().value()
    }

    /// Returns the next expected incoming (target) sequence number.
    #[must_use]
    pub fn next_target_seq(&self) -> u64 {
        self.runtime.sequences.next_target_seq().value()
    }

    /// Returns how many inbound application messages the session has
    /// accepted in sequence and handed to
    /// [`Application::from_app`](crate::Application::from_app) since it
    /// became Active.
    ///
    /// It counts when the session reads the message, not when `from_app`
    /// returns, so it is the counterparty's sending rate as the session sees
    /// it. Read it twice to get the rate over any window the application
    /// chooses: an acceptor that protects itself can then refuse
    /// over-rate messages in `from_app`, with a `RejectReason` that the
    /// session sends as a Reject (3). Messages refused for their application
    /// version, and messages inside a sequence gap, are not counted; a
    /// message the counterparty resends after a gap is counted once, when
    /// it is accepted. The count is per session and starts at 0 on every new
    /// session.
    #[must_use]
    pub fn inbound_app_messages(&self) -> u64 {
        self.runtime.inbound_app_messages.load(Ordering::Relaxed)
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
