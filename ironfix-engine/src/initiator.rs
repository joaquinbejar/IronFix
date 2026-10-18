/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Client-side (initiator) FIX engine: TCP dial, framing, and a live
//! session reactor.
//!
//! [`Initiator::connect`] dials the counterparty over TCP, frames the byte
//! stream with [`ironfix_transport::FixCodec`], drives the
//! [`ironfix_session`] typestate machine through
//! `connect() -> send_logon() -> on_logon_ack()`, and spawns a background
//! reactor task that owns the socket. The returned [`Connection`] handle is
//! the outbound message sink and exposes `wait_closed()` / `is_timed_out()`.
//!
//! Reconnection is deliberately out of scope: the consumer owns supervision
//! and backoff, and calls [`Initiator::connect`] again for a new session.
//!
//! # Inbound conformance
//!
//! Every inbound frame is checked in this order: decode, `MsgSeqNum` (34)
//! presence, counterparty identity (49/56, plus 50/57 when configured),
//! `SendingTime` (52) accuracy, then heartbeat bookkeeping, then sequence
//! validation. Identity and clock come before the heartbeat bookkeeping
//! deliberately — traffic from the wrong counterparty, or from one whose clock
//! is wrong, must not keep the session alive, reach the [`Application`], or
//! move sequence state.
//!
//! Both of those failures end the session after a Reject and a Logout, because
//! both are systemic rather than per-message: a peer that is cross-wired, or
//! whose clock is two minutes out, will be so on its next message too.
//!
//! A *garbled* frame, by contrast, is per-message and is ignored: the codec
//! skips it, or the engine does when its header frames but does not decode
//! (see the crate-level docs). It consumes no `MsgSeqNum`, and the gap is
//! recovered by `ResendRequest`. While waiting for the Logon ack, a garbled ack
//! is skipped, and so is one whose body does not decode; the wait continues
//! against the same [`SessionConfig::logon_timeout`], so an ack that never
//! arrives intact ends in [`EngineError::LogonTimeout`].
//!
//! # Bounded recovery
//!
//! A gap is answered with a `ResendRequest` (2), and a request that goes
//! unanswered does not wait forever: it is retried every
//! [`SessionConfig::resend_timeout`] up to
//! [`SessionConfig::resend_attempt_limit`] attempts, after which the session is
//! logged out. Without that bound a peer that keeps sending gapped frames holds
//! a session open indefinitely — the frames refresh the heartbeat clock, so
//! nothing times out, while the inbound expectation never moves and nothing
//! reaches the application.
//!
//! # Heartbeats
//!
//! The `HeartBtInt` (108) confirmed on the Logon ack wins, but it is
//! counterparty-controlled and drives every liveness timer, so it is bounded
//! by [`ironfix_session::heartbeat::negotiate_interval`]: a confirmed interval
//! above [`ironfix_session::heartbeat::MAX_HEARTBEAT_INTERVAL_SECS`] that is
//! not simply an echo of what this side requested fails the handshake with a
//! Reject (reason 5, `RefTagID` 108) and a Logout. `108=0` is legal and means
//! "do not heartbeat": the reactor then emits no Heartbeat, sends no
//! TestRequest, and never times the session out.
//!
//! Once a TestRequest is outstanding, **any** inbound frame the session
//! accepts stops the timeout countdown; a Heartbeat echoing the `TestReqID` is
//! the positive confirmation. See the `ironfix_session::heartbeat` module
//! documentation for why the rule is that broad.
//!
//! Sequence recovery follows `doc/fix_operations.md`: a `SequenceReset` with
//! `GapFillFlag` (123) = Y is an ordinary sequenced message and is validated
//! against its own `MsgSeqNum`, while Reset mode alone may ignore it; an
//! inbound `ResendRequest` is answered within the bound set by `EndSeqNo`.
//!
//! # Resend and the message store
//!
//! [`Initiator::with_store`] attaches a [`MessageStore`]. Every sequenced
//! outbound frame is then filed under its `MsgSeqNum` before it goes on the
//! wire, and an inbound `ResendRequest` replays the stored application
//! messages with `PossDupFlag` (43) = Y and their original `SendingTime` in
//! `OrigSendingTime` (122). Administrative messages in the range, and any
//! sequence number the store cannot produce, are covered by
//! `SequenceReset`-GapFill, so the counterparty's expectation always lands
//! exactly where the request asked it to.
//!
//! **Without a store nothing can be replayed** and the whole requested range
//! is answered with one gap fill.
//!
//! Store writes are ordered (frame and next sender number before the bytes;
//! next target number before an inbound message is acted on) and fallible.
//! [`Initiator::with_store_failure_policy`] chooses what a failed write means:
//! carry on with a warning (the default), or fail closed, writing nothing the
//! store has not accepted. See the [`persistence`](crate::persistence) module.
//!
//! All sequence arithmetic goes through the checked
//! [`SequenceManager::try_allocate_sender_seq`] /
//! [`SequenceManager::try_increment_target_seq`]; an exhausted counter tears
//! the session down rather than wrapping. A sender number is spent only once
//! the frame that carries it exists, so a body with no legal wire form is a
//! dropped message rather than a hole the counterparty must resend over.
//!
//! # What blocks the reactor, and what does not
//!
//! The reactor is a single task owning the socket. Two things used to be able
//! to park it indefinitely, and neither can now:
//!
//! - **A stalled peer.** A counterparty that stops reading closes its receive
//!   window and parks a socket write forever. Every write is therefore bounded
//!   by [`Initiator::with_write_timeout`], and its expiry closes the session —
//!   the same verdict heartbeat detection would have reached, reached in
//!   bounded time.
//! - **A slow `from_app`.** Inbound application messages are handed to a
//!   separate dispatcher task over a bounded queue
//!   ([`Initiator::with_app_queue_capacity`]), so an application handler never
//!   delays a socket read, a heartbeat, or timeout detection.
//!
//! `to_admin`, `to_app` and `from_admin` still run inline, because each one's
//! result decides what the reactor does next. See [`Application`] for the
//! ordering that buys and the ordering it costs.
//!
//! So do the calls to an attached store: whether a frame may be written, or a
//! message acted on, depends on the store accepting the write first. A slow
//! store therefore delays the session for as long as each call takes. Every
//! call is bounded by [`Initiator::with_store_timeout`], and an overrun is a
//! failed write under the [`StoreFailurePolicy`].
//!
//! # Example
//!
//! ```no_run
//! use ironfix_core::message::MsgType;
//! use ironfix_core::types::CompId;
//! use ironfix_engine::application::NoOpApplication;
//! use ironfix_engine::{Initiator, OutboundMessage};
//! use ironfix_session::SessionConfig;
//! use std::sync::Arc;
//!
//! # async fn run() -> Result<(), ironfix_engine::EngineError> {
//! let config = SessionConfig::new(
//!     CompId::new("CLIENT").unwrap(),
//!     CompId::new("VENUE").unwrap(),
//!     "FIX.4.4",
//! );
//! let initiator = Initiator::new(config, Arc::new(NoOpApplication));
//! let connection = initiator.connect("127.0.0.1:9876").await?;
//!
//! let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
//! order.push_str(11, "ORDER-1");
//! connection.send(order).await?;
//!
//! connection.logout().await?;
//! connection.wait_closed().await;
//! # Ok(())
//! # }
//! ```

use crate::application::{Application, NoOpApplication, RejectReason, SessionId};
use crate::connection::{Connection, SessionRuntime};
use crate::error::EngineError;
use crate::persistence::{
    HandshakeStore, PersistedCounters, SessionStore, StoreFailurePolicy, timed,
};
use crate::reactor::{
    DEFAULT_APP_QUEUE_CAPACITY, DEFAULT_OUTBOUND_CAPACITY, DEFAULT_WRITE_TIMEOUT, HandshakeRead,
    SessionParams, TICK_INTERVAL, lock_heartbeat, read_handshake_frame, refuse_handshake,
    send_handshake_admin, session_codec, spawn_session,
};
use crate::wire::{self, MessageFactory, PeerIdentity, SendingTimeGuard, UnsupportedVersion};
use ironfix_core::error::DecodeError;
use ironfix_core::message::MsgType;
use ironfix_core::version::FixVersion;
use ironfix_session::config::SessionConfigError;
use ironfix_session::heartbeat::negotiate_interval;
use ironfix_session::sequence::{SequenceCounter, SequenceExhausted, SequenceResult};
use ironfix_session::{Disconnected, HeartbeatManager, SequenceManager, Session, SessionConfig};
use ironfix_store::MessageStore;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::time::timeout;
use tokio_util::codec::Framed;

/// Client-side FIX engine.
///
/// Owns the session configuration and the [`Application`] callbacks. Each
/// call to [`Initiator::connect`] establishes one live session and returns
/// a [`Connection`] handle for it.
pub struct Initiator<A: Application = NoOpApplication> {
    /// Session configuration.
    config: SessionConfig,
    /// Application callbacks.
    application: Arc<A>,
    /// Session identifier derived from the configuration.
    session_id: SessionId,
    /// The configured FIX version, or why it cannot be framed. Resolved once
    /// at construction and reported by [`Initiator::connect`] before dialling.
    version: Result<FixVersion, UnsupportedVersion>,
    /// Whether the configuration is usable. Resolved once at construction and
    /// reported by [`Initiator::connect`] before dialling, so a knob that
    /// would corrupt the session's own messages never reaches a socket.
    config_check: Result<(), SessionConfigError>,
    /// TCP connect timeout.
    connect_timeout: Duration,
    /// Bound on a single socket write.
    write_timeout: Duration,
    /// Initial (sender, target) sequence numbers for session continuity.
    initial_sequences: Option<(u64, u64)>,
    /// Capacity of the outbound command queue.
    outbound_capacity: usize,
    /// Capacity of the inbound application queue.
    app_queue_capacity: usize,
    /// Optional message store: outbound frames are filed here and replayed
    /// from here when the counterparty asks for a resend.
    store: Option<Arc<dyn MessageStore>>,
    /// What a failed write to `store` means.
    store_policy: StoreFailurePolicy,
    /// Bound on each store call, or `None` for the write timeout.
    store_timeout: Option<Duration>,
    /// Set when a session's close-time store reset failed: the next
    /// [`Initiator::connect`] must reset the store before anything else.
    reset_owed: Arc<AtomicBool>,
}

/// Written by hand rather than derived: `dyn MessageStore` is not `Debug`, and
/// requiring it of every implementation to print one field is the wrong trade.
impl<A: Application> std::fmt::Debug for Initiator<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Initiator")
            .field("config", &self.config)
            .field("session_id", &self.session_id)
            .field("version", &self.version)
            .field("connect_timeout", &self.connect_timeout)
            .field("write_timeout", &self.write_timeout)
            .field("initial_sequences", &self.initial_sequences)
            .field("outbound_capacity", &self.outbound_capacity)
            .field("app_queue_capacity", &self.app_queue_capacity)
            .field("store", &self.store.is_some())
            .field("store_policy", &self.store_policy)
            .field(
                "store_timeout",
                &self.store_timeout.unwrap_or(self.write_timeout),
            )
            .field("reset_owed", &self.reset_owed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// What [`Initiator::connect`] starts a session from.
struct Seeded {
    /// The sequence counters.
    sequences: SequenceManager,
    /// The counter values the store already holds.
    persisted: PersistedCounters,
    /// Whether the Logon declares `ResetSeqNumFlag` (141) = Y: configured
    /// with `reset_on_logon`, or owed by an earlier session.
    reset_logon: bool,
}

impl<A: Application + 'static> Initiator<A> {
    /// Creates a new initiator.
    ///
    /// The configuration is validated here and the verdict is reported by
    /// [`Initiator::connect`], which refuses to dial with an unusable one.
    /// Building it through [`ironfix_session::SessionConfigBuilder`] surfaces
    /// the same errors earlier.
    ///
    /// # Arguments
    /// * `config` - The session configuration
    /// * `application` - The application callback handler
    #[must_use]
    pub fn new(config: SessionConfig, application: Arc<A>) -> Self {
        let mut session_id = SessionId::new(
            config.begin_string.clone(),
            config.sender_comp_id.as_str(),
            config.target_comp_id.as_str(),
        );
        if let Some(sub) = &config.sender_sub_id {
            session_id = session_id.with_sender_sub_id(sub.clone());
        }
        if let Some(sub) = &config.target_sub_id {
            session_id = session_id.with_target_sub_id(sub.clone());
        }
        let version = wire::wire_version(&config.begin_string);
        let config_check = config.validate();

        Self {
            config,
            application,
            session_id,
            version,
            config_check,
            connect_timeout: Duration::from_secs(30),
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            initial_sequences: None,
            outbound_capacity: DEFAULT_OUTBOUND_CAPACITY,
            app_queue_capacity: DEFAULT_APP_QUEUE_CAPACITY,
            store: None,
            store_policy: StoreFailurePolicy::Continue,
            store_timeout: None,
            reset_owed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Attaches a message store to the session.
    ///
    /// With a store the engine files every sequenced outbound frame under its
    /// `MsgSeqNum` and, on an inbound `ResendRequest` (35=2), replays the
    /// stored **application** messages with `PossDupFlag` (43) = Y and the
    /// original `SendingTime` in `OrigSendingTime` (122). Administrative
    /// messages, and any sequence number the store cannot produce, are covered
    /// by `SequenceReset`-GapFill instead — see
    /// [`Initiator::connect`](Initiator::connect) and
    /// `doc/fix_operations.md`, "Resend Request".
    ///
    /// Without a store the engine has nothing to replay and answers the whole
    /// requested range with one gap fill.
    ///
    /// The store also carries sequence numbers: unless `reset_on_logon` is set
    /// or [`Initiator::with_initial_sequences`] is called, the session starts
    /// from the counters the store reports, and both counters are persisted
    /// back into it as the session runs, in the order described in the
    /// [`persistence`](crate::persistence) module. Note that
    /// [`MemoryStore`](ironfix_store::MemoryStore) is the only implementation
    /// today and is **not** persistent, so this does not yet survive a restart.
    ///
    /// A failed write to the store is handled by
    /// [`Initiator::with_store_failure_policy`]; the default carries on with a
    /// warning. Every store call is bounded by
    /// [`Initiator::with_store_timeout`].
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn MessageStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Sets what a failed write to the attached store means (default
    /// [`StoreFailurePolicy::Continue`]).
    ///
    /// With [`StoreFailurePolicy::CloseSession`] the engine never puts a frame
    /// on the wire, or acts on an inbound message, that the store has not
    /// accepted: a failure during the Logon handshake makes
    /// [`Initiator::connect`] return [`EngineError::Store`], and one during the
    /// session closes it without writing the frame concerned. Without a store
    /// this has no effect.
    ///
    /// # Arguments
    /// * `policy` - The policy for store write failures
    #[must_use]
    pub const fn with_store_failure_policy(mut self, policy: StoreFailurePolicy) -> Self {
        self.store_policy = policy;
        self
    }

    /// Sets how long a single call to the attached store may take before it
    /// counts as failed (default: the write timeout, see
    /// [`Initiator::with_write_timeout`]).
    ///
    /// The session awaits every store call inline, so a store that stalls
    /// stalls the session with it: no socket read, no heartbeat and no timeout
    /// detection until the call returns. The bound turns a stall into
    /// [`StoreError::Timeout`](ironfix_core::error::StoreError::Timeout). A
    /// write that overruns is handled by the [`StoreFailurePolicy`] like any
    /// other failed write; a reset or refresh that overruns fails the connect
    /// with [`EngineError::Store`], whatever the policy; and a resend read
    /// that overruns is answered with a gap fill. Without a store this has no
    /// effect.
    ///
    /// A write that overruns may still land later, so it also leaves a reset
    /// owed: the next session resets the store and logs on with
    /// `ResetSeqNumFlag` (141) = Y. Reusing the store is safe only if it
    /// applies its mutations in call order even when a call is dropped (see
    /// the [`persistence`](crate::persistence) module).
    ///
    /// A zero timeout is raised to one tick, as for the write timeout: a call
    /// given no time at all can never succeed.
    ///
    /// # Arguments
    /// * `timeout` - Maximum duration of one store call
    #[must_use]
    pub fn with_store_timeout(mut self, timeout: Duration) -> Self {
        self.store_timeout = Some(timeout.max(TICK_INTERVAL));
        self
    }

    /// The bound on one store call: the configured store timeout, or the
    /// write timeout when none was set.
    #[must_use]
    fn store_timeout(&self) -> Duration {
        self.store_timeout.unwrap_or(self.write_timeout)
    }

    /// Sets the TCP connect timeout (default 30s).
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets how long a single socket write may take before the session is
    /// closed (default 10s).
    ///
    /// A counterparty that stops reading closes its TCP receive window, and a
    /// write into a closed window never completes. Without a bound the reactor
    /// parks inside that write with its liveness timers, so the session hangs
    /// instead of being declared dead. Expiry closes the session with
    /// [`EngineError::WriteTimeout`].
    ///
    /// A zero timeout is raised to one tick: a write that is given no time at
    /// all can never succeed.
    ///
    /// # Arguments
    /// * `timeout` - Maximum duration of one write
    #[must_use]
    pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = timeout.max(TICK_INTERVAL);
        self
    }

    /// Sets the capacity of the inbound application queue (default 1024).
    ///
    /// Inbound application messages are handed to a dispatcher task over this
    /// queue so that a slow [`Application::from_app`] cannot stall socket
    /// reads or heartbeat generation. Messages are delivered in ascending
    /// `MsgSeqNum` order.
    ///
    /// **Lag policy:** when the queue is full the session is closed rather than
    /// the message silently dropped. The frame is offered to the dispatcher
    /// *before* the inbound sequence expectation advances past it, so the close
    /// leaves the counterparty free to resend from that number. Raise the
    /// capacity for an application that legitimately bursts.
    ///
    /// **Memory:** the bound is on message count, not bytes, and each queued
    /// frame retains up to [`SessionConfig::max_message_size`]. The worst-case
    /// retained memory is `capacity * max_message_size` — with the default
    /// capacity of 1024 that is 1 GiB at the default 1 MiB frame size and 64 GiB
    /// at the 64 MiB ceiling — so raise this and `max_message_size` together
    /// with that product in mind.
    ///
    /// # Arguments
    /// * `capacity` - Queue depth in messages, at least 1
    #[must_use]
    pub fn with_app_queue_capacity(mut self, capacity: usize) -> Self {
        self.app_queue_capacity = capacity.max(1);
        self
    }

    /// Seeds the session with initial sequence numbers, for continuity with
    /// a previous session (e.g. after a reconnect supervised by the
    /// consumer). Ignored when `reset_on_logon` is set.
    ///
    /// Both values must be at least 1: FIX numbers messages from 1, and a
    /// seeded `MsgSeqNum` (34) of 0 would be rejected by every conforming
    /// counterparty. A zero seed that would actually be used is refused by
    /// [`Initiator::connect`] with [`EngineError::InvalidInitialSequence`],
    /// before the socket is dialled.
    ///
    /// The seed outranks the counters an attached store reports. Under
    /// [`StoreFailurePolicy::CloseSession`], though, a sender seed below the
    /// store's next sender number is refused with
    /// [`EngineError::InitialSequenceBelowStore`], before anything is written:
    /// the store has frames filed at those numbers, so the counterparty has
    /// seen them, and reusing one would send a different message under a
    /// `MsgSeqNum` it already holds.
    ///
    /// # Arguments
    /// * `sender_seq` - Next outgoing sequence number, `>= 1`
    /// * `target_seq` - Next expected incoming sequence number, `>= 1`
    #[must_use]
    pub fn with_initial_sequences(mut self, sender_seq: u64, target_seq: u64) -> Self {
        self.initial_sequences = Some((sender_seq, target_seq));
        self
    }

    /// Sets the capacity of the outbound message queue (default 1024).
    #[must_use]
    pub fn with_outbound_capacity(mut self, capacity: usize) -> Self {
        self.outbound_capacity = capacity.max(1);
        self
    }

    /// Whether an earlier session of this `Initiator` left a store reset owed
    /// (see the [`persistence`](crate::persistence) module).
    #[must_use]
    fn reset_is_owed(&self) -> bool {
        self.store.is_some() && self.reset_owed.load(Ordering::Acquire)
    }

    /// Decides the sequence numbers this session starts from, whether its
    /// Logon declares a reset, and which counters the store already holds.
    ///
    /// By priority, highest first:
    ///
    /// 1. A reset owed by an earlier session of this `Initiator` (a close-time
    ///    reset, or the reset for a counterparty's `ResetSeqNumFlag` (141),
    ///    that failed): the store is reset and the Logon declares
    ///    `ResetSeqNumFlag` = Y and starts at 1, so both sides restart the
    ///    sequence together. The record is cleared once that Logon is
    ///    acknowledged, not here: a connect that fails before then still owes
    ///    the reset.
    /// 2. `reset_on_logon` — the same reset and Logon, by configuration.
    ///    Keeping the old messages would leave two different streams filed
    ///    under the same numbers, and a later `ResendRequest` could not tell
    ///    them apart.
    /// 3. [`Initiator::with_initial_sequences`] — an explicit instruction from
    ///    the consumer outranks whatever the store remembers. Under
    ///    [`StoreFailurePolicy::CloseSession`] the store is refreshed first and
    ///    a sender seed below its next sender number is refused.
    /// 4. The store's own counters, refreshed from its backing medium first.
    ///    Those are values the store already holds, so they are recorded as
    ///    written and the session does not write them back unchanged.
    /// 5. A fresh session at 1/1.
    ///
    /// Every store call is bounded by the store timeout.
    ///
    /// # Errors
    /// Returns [`EngineError::Store`] if the store cannot be reset (cases 1 and
    /// 2) or refreshed (case 4, and case 3 under
    /// [`StoreFailurePolicy::CloseSession`]), whatever the policy: starting at
    /// 1 with the previous stream still filed would let a later
    /// `ResendRequest` replay it, and starting against un-refreshed counters
    /// would reuse a `MsgSeqNum` the counterparty has already seen. The session
    /// is refused rather than silently started from a counter the store could
    /// not vouch for. Returns [`EngineError::InitialSequenceBelowStore`] for a
    /// sender seed below the store's next sender number under
    /// [`StoreFailurePolicy::CloseSession`].
    async fn seed_sequences(&self) -> Result<Seeded, EngineError> {
        let store_timeout = self.store_timeout();
        let store = self.store.as_deref();
        let mut persisted = PersistedCounters::default();

        let owed = self.reset_is_owed();
        if owed || self.config.reset_on_logon {
            if store.is_some() {
                // Owed from before the call until the Logon declaring the
                // reset is acknowledged: a connect dropped while the reset is
                // pending leaves it owed, and so does one that fails later.
                self.reset_owed.store(true, Ordering::Release);
            }
            if let Some(store) = store
                && let Err(err) = timed(store_timeout, store.reset()).await
            {
                tracing::error!(
                    session = %self.session_id,
                    owed,
                    error = %err,
                    "cannot reset the store for a ResetSeqNumFlag logon: refusing the session \
                     rather than starting at 1 with the previous stream still filed"
                );
                return Err(EngineError::Store(err));
            }
            return Ok(Seeded {
                sequences: SequenceManager::new(),
                persisted,
                reset_logon: true,
            });
        }

        if let Some((sender, target)) = self.initial_sequences {
            if let Some(store) = store
                && self.store_policy.closes_session()
            {
                self.refresh_store(store, store_timeout).await?;
                let stored = store.next_sender_seq();
                if sender < stored {
                    tracing::error!(
                        session = %self.session_id,
                        seeded = sender,
                        stored,
                        "initial sender sequence number is below the store's next sender number: \
                         refusing the session rather than reusing a MsgSeqNum already sent"
                    );
                    return Err(EngineError::InitialSequenceBelowStore {
                        seeded: sender,
                        stored,
                    });
                }
            }
            // A zero seed is refused before dialling, so both are non-zero here;
            // the floor keeps the conversion total.
            return Ok(Seeded {
                sequences: SequenceManager::with_initial(
                    NonZeroU64::new(sender).unwrap_or(NonZeroU64::MIN),
                    NonZeroU64::new(target).unwrap_or(NonZeroU64::MIN),
                ),
                persisted,
                reset_logon: false,
            });
        }

        let Some(store) = store else {
            return Ok(Seeded {
                sequences: SequenceManager::new(),
                persisted,
                reset_logon: false,
            });
        };
        self.refresh_store(store, store_timeout).await?;
        let sender = store.next_sender_seq();
        let target = store.next_target_seq();
        // MsgSeqNum starts at 1, so a store reporting 0 is reporting a number
        // that names no message. Floor it rather than number a message 0; a
        // floored value is not one the store holds, so it is not recorded.
        if sender >= 1 {
            persisted.record_sender(sender);
        }
        if target >= 1 {
            persisted.record_target(target);
        }
        Ok(Seeded {
            sequences: SequenceManager::with_initial(
                NonZeroU64::new(sender).unwrap_or(NonZeroU64::MIN),
                NonZeroU64::new(target).unwrap_or(NonZeroU64::MIN),
            ),
            persisted,
            reset_logon: false,
        })
    }

    /// Refreshes the store from its backing medium, bounded by the store
    /// timeout.
    ///
    /// # Errors
    /// [`EngineError::Store`] if the refresh fails or overruns, whatever the
    /// policy: the counters it would have recovered are what the session is
    /// about to number its messages from.
    async fn refresh_store(
        &self,
        store: &dyn MessageStore,
        store_timeout: Duration,
    ) -> Result<(), EngineError> {
        timed(store_timeout, store.refresh()).await.map_err(|err| {
            tracing::error!(
                session = %self.session_id,
                error = %err,
                "cannot refresh the store: refusing the session rather than starting against \
                 unknown counters and risking a reused MsgSeqNum"
            );
            EngineError::Store(err)
        })
    }

    /// Returns the session configuration.
    #[must_use]
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Returns the session identifier.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Dials the counterparty, completes the Logon handshake, and spawns
    /// the session reactor.
    ///
    /// On success the session is Active: `on_logon` has fired and the
    /// returned [`Connection`] can send application messages. The reactor
    /// owns the socket and handles heartbeats, TestRequests, sequence
    /// validation, and admin replies until the session closes.
    ///
    /// # Dropping the handle logs out
    ///
    /// The reactor stops when the last [`Connection`] clone is dropped: it
    /// reads that as "nobody can drive this session any more" and performs a
    /// graceful Logout rather than leaving a task holding a socket forever.
    /// A consumer that wants the session to outlive its handle must keep one
    /// alive — typically by holding it until [`Connection::wait_closed`]
    /// returns.
    ///
    /// # One session at a time, with a store
    ///
    /// With a store attached, call `connect` again only once the previous
    /// session's [`Connection::wait_closed`] has returned. Until then the
    /// closing session still writes to the store (the close-time reset of
    /// `reset_on_logout` / `reset_on_disconnect` and the last counter values)
    /// and may record a reset owed to the next session; a session started
    /// beside it would share the store with it and could miss that record.
    /// The engine does not enforce this.
    ///
    /// # Arguments
    /// * `addr` - The counterparty address to dial
    ///
    /// # Errors
    /// Returns an [`EngineError`] if the dial, framing, or Logon handshake
    /// fails. An ack that never arrives intact within
    /// [`SessionConfig::logon_timeout`], including one that arrives only
    /// garbled, is [`EngineError::LogonTimeout`]. Beyond timeouts and
    /// transport failures that includes
    /// [`EngineError::IdentityMismatch`], when the ack's CompIDs do not match
    /// the configured session, and [`EngineError::SequenceExhausted`], when a
    /// sequence counter has reached `u64::MAX` and the session must be reset
    /// before it can number another message. A `BeginString` this engine
    /// cannot frame conformantly is refused up front with
    /// [`EngineError::UnsupportedVersion`], an unusable configuration with
    /// [`EngineError::Config`], and a zero initial sequence seed with
    /// [`EngineError::InvalidInitialSequence`], all before the socket is
    /// dialled.
    pub async fn connect(&self, addr: impl ToSocketAddrs) -> Result<Connection, EngineError> {
        // Refuse before dialling: a knob outside its documented range corrupts
        // the session's own messages — an identity string carrying SOH breaks
        // every header, and a fractional HeartBtInt negotiates one interval
        // while the local timers run another.
        if let Err(err) = &self.config_check {
            return Err(EngineError::Config(err.clone()));
        }

        // Refuse before dialling: an unsupported version cannot produce a
        // conforming Logon, and guessing one would put a fabricated version on
        // the wire.
        let version = match &self.version {
            Ok(version) => *version,
            Err(err) => {
                return Err(EngineError::UnsupportedVersion {
                    version: err.version.clone(),
                    detail: err.detail.clone(),
                });
            }
        };

        // Refuse before dialling: a seeded sequence number of zero would put
        // MsgSeqNum (34) = 0 on the wire, which every conforming counterparty
        // rejects. The seed is ignored entirely when the Logon declares a reset
        // (reset_on_logon, or a reset owed by an earlier session), so a zero
        // is only refused when it would actually be used. The validated seed
        // is applied by `seed_sequences`, which reads the same fields; this is
        // only the guard.
        if let Some((sender, target)) = self.initial_sequences
            && !self.config.reset_on_logon
            && !self.reset_is_owed()
        {
            NonZeroU64::new(sender).ok_or(EngineError::InvalidInitialSequence {
                counter: SequenceCounter::Sender,
            })?;
            NonZeroU64::new(target).ok_or(EngineError::InvalidInitialSequence {
                counter: SequenceCounter::Target,
            })?;
        }

        let session_id = self.session_id.clone();
        self.application.on_create(&session_id).await;

        // Typestate: Disconnected -> Connecting.
        let session = Session::<Disconnected>::new(session_id.to_string()).connect();

        let stream = match timeout(self.connect_timeout, TcpStream::connect(addr)).await {
            Err(_) => {
                let _ = session.disconnect();
                return Err(EngineError::ConnectTimeout(self.connect_timeout));
            }
            Ok(Err(err)) => {
                let _ = session.disconnect();
                return Err(err.into());
            }
            Ok(Ok(stream)) => stream,
        };
        let _ = stream.set_nodelay(true);

        let mut framed = Framed::new(stream, session_codec(&self.config, version));

        // Seeding fails closed: a store that cannot be reset or refreshed leaves
        // the session unable to vouch for its own counters, so it is refused
        // here rather than started from a number that could collide with a
        // stream still on file.
        let Seeded {
            sequences,
            persisted,
            reset_logon,
        } = match self.seed_sequences().await {
            Ok(seeded) => seeded,
            Err(err) => {
                let _ = session.disconnect();
                return Err(err);
            }
        };
        let runtime = Arc::new(SessionRuntime {
            sequences,
            heartbeat: Mutex::new(HeartbeatManager::new(self.config.heartbeat_interval)),
        });
        let mut factory = MessageFactory::new(&self.config, version);
        let identity = PeerIdentity::new(&self.config);
        let sending_time = SendingTimeGuard::new(&self.config);
        let write_timeout = self.write_timeout;
        let store_timeout = self.store_timeout();
        // Every handshake write goes through this binding, which also records
        // the counter values written, for the reactor to start from.
        let mut store = self.store.as_deref().map(|store| HandshakeStore {
            store: SessionStore::new(store, self.store_policy, store_timeout, &self.reset_owed),
            persisted,
        });

        // Typestate: Connecting -> LogonSent.
        //
        // `to_admin` runs on the message before it is framed, so a stamped
        // Username/Password reaches the wire — the callback's whole purpose.
        // A reset the store owes is declared like a configured one, so the
        // counterparty restarts the sequence with us instead of reading our
        // MsgSeqNum 1 as too low.
        let logon = factory.logon(self.config.heartbeat_interval_secs(), reset_logon);
        if let Err(err) = send_handshake_admin(
            self.application.as_ref(),
            &session_id,
            &mut framed,
            &mut factory,
            &runtime.sequences,
            store.as_mut(),
            write_timeout,
            logon,
        )
        .await
        {
            let _ = session.disconnect();
            return Err(err);
        }
        lock_heartbeat(&runtime).on_message_sent();
        let session = session.send_logon();

        // Await the Logon acknowledgement. Garbled frames are skipped, and the
        // logon timeout covers the whole wait, so an ack that never arrives
        // intact is a LogonTimeout.
        let ack =
            match read_handshake_frame(&mut framed, self.config.logon_timeout, &session_id).await {
                HandshakeRead::Frame(frame) => frame,
                HandshakeRead::TimedOut => {
                    let _ = session.on_logon_reject();
                    return Err(EngineError::LogonTimeout(self.config.logon_timeout));
                }
                HandshakeRead::Closed => {
                    let _ = session.on_logon_reject();
                    return Err(EngineError::Closed);
                }
                HandshakeRead::Codec(err) => {
                    let _ = session.on_logon_reject();
                    return Err(err.into());
                }
            };

        // (gap start, high-water) of a gap detected in the Logon ack itself.
        let mut pending_resend: Option<(u64, u64)> = None;
        {
            let raw = wire::decode_frame(&ack)?;
            match raw.msg_type() {
                MsgType::Logon => {}
                MsgType::Logout | MsgType::Reject => {
                    let reason = raw
                        .get_field_str(58)
                        .unwrap_or("logon rejected by counterparty")
                        .to_string();
                    let _ = session.on_logon_reject();
                    return Err(EngineError::LogonRejected { reason });
                }
                other => {
                    let msg_type = other.as_str().to_string();
                    let _ = session.on_logon_reject();
                    return Err(EngineError::UnexpectedMessage { msg_type });
                }
            }

            // BeginString before anything else the ack claims: an
            // acknowledgement in a different FIX dialect than this session was
            // configured for is not our acknowledgement, no matter what its
            // CompIDs or MsgSeqNum say. The configured transport BeginString is
            // the value used for outbound framing -- FIXT.1.1 for a 5.0
            // session -- so that, not FIX.5.0*, is what a conforming ack
            // carries. A mismatch aborts the handshake with a typed error
            // rather than taking the session Active under the wrong protocol
            // version.
            match raw.begin_string() {
                Ok(begin_string) if begin_string == version.begin_string() => {}
                Ok(begin_string) => {
                    let received = begin_string.to_string();
                    let _ = session.on_logon_reject();
                    return Err(EngineError::BeginStringMismatch {
                        expected: version.begin_string().to_string(),
                        received,
                    });
                }
                Err(err) => {
                    let _ = session.on_logon_reject();
                    return Err(err.into());
                }
            }

            // Positional: MsgSeqNum (34) must be in the standard header, the
            // same contract the CompID check enforces on 49/56 and the acceptor
            // handshake already applies. A 34 that appears only after the body
            // is treated as a missing header field rather than accepted as the
            // ack sequence number.
            let Some(ack_seq) = wire::header_seq_num(&raw) else {
                let _ = session.on_logon_reject();
                return Err(EngineError::Sequence(
                    "Logon ack has no valid MsgSeqNum (34) in the standard header".to_string(),
                ));
            };

            // Identity before anything else: a cross-wired acceptor must not
            // be allowed to establish a session or move sequence state.
            if let Err(mismatch) = identity.validate(&raw) {
                let detail = mismatch.to_string();
                let reason = RejectReason::new(9, detail.clone()).with_ref_tag(mismatch.tag);
                let reject = factory.session_reject(ack_seq, MsgType::Logon.as_str(), &reason);
                let logout = factory.logout(Some(&detail));
                let refused = refuse_handshake(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    store.as_mut(),
                    write_timeout,
                    &detail,
                    [reject, logout],
                )
                .await;
                let _ = session.on_logon_reject();
                refused?;
                return Err(EngineError::IdentityMismatch { detail });
            }

            // The clock is checked on the ack for the same reason it is checked
            // on every later frame: a peer whose SendingTime is wildly skewed
            // cannot be trusted to sequence a session, and the handshake is the
            // cheapest place to refuse it.
            if let Err(problem) = sending_time.validate(&raw) {
                let detail = problem.to_string();
                let reason = problem.reject_reason();
                let reject = factory.session_reject(ack_seq, MsgType::Logon.as_str(), &reason);
                let logout = factory.logout(Some(&detail));
                let refused = refuse_handshake(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    store.as_mut(),
                    write_timeout,
                    &detail,
                    [reject, logout],
                )
                .await;
                let _ = session.on_logon_reject();
                refused?;
                return Err(EngineError::SendingTime { detail });
            }

            if let Err(reason) = self.application.from_admin(&raw, &session_id).await {
                let logout = factory.logout(Some(&reason.text));
                let refused = refuse_handshake(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    store.as_mut(),
                    write_timeout,
                    &reason.text,
                    [logout],
                )
                .await;
                let _ = session.on_logon_reject();
                refused?;
                return Err(EngineError::LogonRejected {
                    reason: reason.text,
                });
            }

            // Honor the heartbeat interval confirmed by the counterparty, but
            // only within the bound `negotiate_interval` enforces: 108 is
            // counterparty-controlled and drives every liveness timer in the
            // session. Resolved before the lock is taken, because refusing it
            // has to send a Reject and a Logout.
            //
            // HeartBtInt (108) is a *required* field of the Logon
            // (`doc/fix_operations.md`, "Logon"). An ack that omits it or
            // carries a non-numeric value gives the two sides nothing to agree
            // liveness timing on, so the handshake fails rather than silently
            // establishing the session on the locally configured interval.
            let secs: u64 = match raw.get_field_as::<u64>(108) {
                Ok(secs) => secs,
                Err(err) => {
                    // SessionRejectReason 1 (Required tag missing) for an
                    // absent 108, 6 (Incorrect data format for value) for a
                    // present-but-unparseable one.
                    let (code, detail) = if matches!(err, DecodeError::MissingRequiredField { .. })
                    {
                        (
                            1,
                            "Logon acknowledgement omitted the required HeartBtInt (108)"
                                .to_string(),
                        )
                    } else {
                        (6, err.to_string())
                    };
                    let reason = RejectReason::new(code, detail.clone()).with_ref_tag(108);
                    let reject = factory.session_reject(ack_seq, MsgType::Logon.as_str(), &reason);
                    let logout = factory.logout(Some(&detail));
                    let refused = refuse_handshake(
                        self.application.as_ref(),
                        &session_id,
                        &mut framed,
                        &mut factory,
                        &runtime.sequences,
                        store.as_mut(),
                        write_timeout,
                        &detail,
                        [reject, logout],
                    )
                    .await;
                    let _ = session.on_logon_reject();
                    refused?;
                    return Err(EngineError::HeartbeatInterval { detail });
                }
            };
            let negotiated = match negotiate_interval(self.config.heartbeat_interval, secs) {
                Ok(interval) => interval,
                Err(err) => {
                    let detail = err.to_string();
                    let reason = RejectReason::new(5, detail.clone()).with_ref_tag(108);
                    let reject = factory.session_reject(ack_seq, MsgType::Logon.as_str(), &reason);
                    let logout = factory.logout(Some(&detail));
                    let refused = refuse_handshake(
                        self.application.as_ref(),
                        &session_id,
                        &mut framed,
                        &mut factory,
                        &runtime.sequences,
                        store.as_mut(),
                        write_timeout,
                        &detail,
                        [reject, logout],
                    )
                    .await;
                    let _ = session.on_logon_reject();
                    refused?;
                    return Err(EngineError::HeartbeatInterval { detail });
                }
            };
            {
                let mut heartbeat = lock_heartbeat(&runtime);
                heartbeat.on_message_received(false, None);
                if negotiated != heartbeat.interval() {
                    tracing::info!(
                        session = %session_id,
                        heartbeat_secs = negotiated.as_secs(),
                        "using heartbeat interval confirmed by counterparty"
                    );
                    *heartbeat = HeartbeatManager::new(negotiated);
                }
            }

            // ResetSeqNumFlag (141) on the ack is a counterparty-driven
            // reset and must be honored before MsgSeqNum is validated,
            // otherwise the ack's 34=1 reads as fatally too low against
            // continuity-seeded counters.
            if raw.get_field_str(141) == Some("Y") {
                // FIX requires MsgSeqNum = 1 on a Logon carrying
                // ResetSeqNumFlag = Y: the reset and the number it arrives
                // under have to agree. A peer that declares a reset and then
                // numbers the message anything else is describing two
                // different streams, so the handshake fails rather than
                // guessing which half to believe.
                if ack_seq != 1 {
                    let _ = session.on_logon_reject();
                    return Err(EngineError::Sequence(format!(
                        "Logon ack set ResetSeqNumFlag=Y but carried MsgSeqNum {ack_seq}, not 1"
                    )));
                }
                tracing::info!(
                    session = %session_id,
                    "counterparty set ResetSeqNumFlag on the Logon ack: resetting sequence numbers"
                );
                // Our Logon did not ask for the reset, so the store still holds
                // the previous stream and its counters. It is reset now and set
                // to the new stream's counters (our Logon and this ack are each
                // side's message 1), in one call, before the session goes
                // Active and before `on_logon`: a connect that fails from here
                // on must not leave a store that a later session would replay
                // the previous stream's frames from into this one.
                //
                // A failure refuses the session whatever the policy, as the
                // other resets do: carrying on would let a resend in the new
                // stream replay the previous stream's frames under the numbers
                // the new one uses. The reset is then owed, so the next connect
                // makes it and declares ResetSeqNumFlag itself.
                if !reset_logon && let Some(handshake) = store.as_mut() {
                    // Owed before the call and cleared only once it has
                    // succeeded: a caller that drops this connect while the
                    // reset is pending runs no error branch, and the next
                    // connect must still make the reset and declare it.
                    self.reset_owed.store(true, Ordering::Release);
                    if let Err(err) = handshake.store.reset_to(&session_id, 2, 2).await {
                        let _ = session.on_logon_reject();
                        return Err(err.into());
                    }
                    self.reset_owed.store(false, Ordering::Release);
                    // The reset replaced whatever was recorded as written.
                    handshake.persisted = PersistedCounters::default();
                    handshake.persisted.record_sender(2);
                    handshake.persisted.record_target(2);
                }
                runtime.sequences.set_target_seq(1);
                // The Logon already on the wire is message 1 of the reset
                // outbound stream; rewinding the sender counter to 1 would
                // re-emit a MsgSeqNum the counterparty has already seen.
                runtime.sequences.set_sender_seq(2);
            }

            match runtime.sequences.validate_incoming(ack_seq) {
                SequenceResult::Ok => {
                    // The receive cursor includes the ack before the session
                    // goes Active on it and before the in-memory expectation
                    // moves, as for every later inbound message.
                    if let Some(handshake) = store.as_mut() {
                        let Some(next) = ack_seq.checked_add(1) else {
                            let _ = session.on_logon_reject();
                            return Err(SequenceExhausted {
                                counter: SequenceCounter::Target,
                            }
                            .into());
                        };
                        if handshake.persisted.target_to_write(next).is_some() {
                            handshake.persisted.record_target(next);
                            if let Err(err) =
                                handshake.store.persist_target(&session_id, next).await
                            {
                                let _ = session.on_logon_reject();
                                return Err(err.into());
                            }
                        }
                    }
                    if let Err(err) = runtime.sequences.try_increment_target_seq() {
                        let _ = session.on_logon_reject();
                        return Err(err.into());
                    }
                }
                SequenceResult::TooLow { expected, received } => {
                    let _ = session.on_logon_reject();
                    return Err(EngineError::Sequence(format!(
                        "logon ack MsgSeqNum too low: expected {expected}, received {received}"
                    )));
                }
                SequenceResult::Gap { expected, received } => {
                    pending_resend = Some((expected, received));
                }
            }
        }

        // The Logon that declared the reset has been acknowledged: no reset is
        // owed any more.
        if reset_logon {
            self.reset_owed.store(false, Ordering::Release);
        }

        // Typestate: LogonSent -> Active.
        let session = session.on_logon_ack();
        self.application.on_logon(&session_id).await;
        tracing::info!(session = %session_id, "FIX session established");

        // Hand the framed socket to the shared reactor. The initiator carries no
        // admission guard, so the guard is `()`. A gap in the Logon ack is
        // requested by the reactor as its first act, so that once `on_logon`
        // has run, a failure to send the request closes the session through
        // the reactor's close path (`on_logout`, the close-time reset, the
        // counters) like any other.
        let params = SessionParams {
            framed,
            session,
            runtime: Arc::clone(&runtime),
            factory,
            identity,
            sending_time,
            config: self.config.clone(),
            application: Arc::clone(&self.application),
            session_id: session_id.clone(),
            store: self.store.clone(),
            store_policy: self.store_policy,
            store_timeout,
            persisted: store
                .map_or_else(PersistedCounters::default, |handshake| handshake.persisted),
            reset_owed: Arc::clone(&self.reset_owed),
            opening_gap: pending_resend,
            write_timeout,
            outbound_capacity: self.outbound_capacity,
            app_queue_capacity: self.app_queue_capacity,
        };
        let (command_tx, closed_rx) = spawn_session(params, ());

        Ok(Connection {
            session_id,
            commands: command_tx,
            closed: closed_rx,
            runtime,
        })
    }
}
