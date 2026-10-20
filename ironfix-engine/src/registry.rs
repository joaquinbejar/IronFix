/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Multi-session acceptor: one listener, many counterparties, each inbound
//! Logon routed to its session by the identity it claims.
//!
//! An [`Acceptor`] is one configured session. A server that fronts many
//! counterparties on one port cannot pick the right `Acceptor` for an inbound
//! connection by itself, because the only thing that identifies the peer is
//! its first Logon, and [`Acceptor::serve`] reads that Logon itself.
//! [`AcceptorRegistry`] reads it once, resolves the session from the
//! identity it claims, and runs that session's handshake on it, unchanged.
//! [`AcceptorRegistry::serve`] takes an accepted `TcpStream`;
//! [`AcceptorRegistry::serve_stream`] takes a stream of any other type the
//! caller has accepted (a TLS stream, a Unix socket, an in-memory pipe), and
//! one registry can route connections of different stream types.
//!
//! # Routing
//!
//! The routing key is the inbound identity, in the Logon's own orientation:
//! its `SenderCompID` (49) is the session's configured `target_comp_id`, its
//! `TargetCompID` (56) the session's `sender_comp_id`, and, when the session
//! configures them, its `SenderSubID` (50), `TargetSubID` (57),
//! `SenderLocationID` (142) and `TargetLocationID` (143) are the session's
//! target and sender sub and location IDs. A sub or location ID the session
//! does not configure places no requirement on the Logon. The routed session
//! then enforces the same identity on every inbound message, its configured
//! sub and location IDs included, so a peer cannot be routed on one identity
//! and send under another. `BeginString` (8) is not part of the key: the
//! routed session checks it, as [`Acceptor::serve`] does.
//!
//! The Logon is not validated yet when it is routed, so its identity is read
//! from the **standard header** only (a 49 or 56 that occurs only in the body
//! names nobody, and a field repeated in the header names nobody either) and
//! every value is bounded **before** any session or the lookup is consulted:
//! 1 to [`MAX_ID_LEN`] bytes of printable ASCII. A Logon that fails is refused
//! with [`EngineError::UnroutableLogon`]. Only the identity fields are ever
//! logged, bounded that way (an invalid one as a short escaped prefix); the
//! Logon itself never is, so `Password` (554), `NewPassword` (925) and
//! `RawData` (96) never reach a log line.
//!
//! [`AcceptorRegistry::register`] refuses a session whose key overlaps one
//! already registered (some Logon could match both), one whose [`SessionId`]
//! is already registered, and one whose store another session already uses,
//! so a Logon matches at most one session, routing never depends on
//! registration order, and every store belongs to one session.
//!
//! # Sessions not known at startup
//!
//! A [`SessionLookup`] set with [`AcceptorRegistry::with_lookup`] is asked
//! about an identity no registered session matches. It may admit the session,
//! by returning the [`Acceptor`] that serves it, refuse it, or report that it
//! cannot decide ([`LookupError`]). An admitted session is held
//! **provisionally** while its first handshake runs, since the lookup admits
//! before [`Application::from_admin`] has authenticated anyone. If that
//! handshake ends before `from_admin` accepts the Logon, and no other
//! connection is routed to the session, the session is evicted: nothing is
//! lost, because before authentication its store is untouched. Once a
//! handshake gets past `from_admin`, the session stays for the registry's
//! lifetime, like a registered one, so its admission slot (one live session at
//! a time) and the record of a reset it owes outlive the connection. See
//! [`SessionLookup`] ("Resource use") for what this costs and how to bound
//! it.
//!
//! # Refusals
//!
//! Before the Logon is routed there is no session: no sequence stream to
//! number a reply from, no store to file one in, and no configured identity to
//! stamp on it. A Logon that cannot be routed (an unroutable identity, an
//! unknown session, a lookup that refuses, fails or does not answer in time,
//! the session cap, a first frame that is not a Logon) is therefore closed
//! **without a reply**, no store is touched and no [`Application`] callback
//! runs. This is the policy ADR-0017 gives an unauthenticated peer when a
//! store is attached, applied here in both modes. These refusals are logged at
//! debug level, since any peer can provoke them at will; a lookup that fails
//! or overruns, returns a session the registry cannot hold, or meets the
//! session cap is logged as a warning, being the operator's to fix.
//!
//! Once routed, the session's own handshake answers the Logon exactly as
//! [`Acceptor::serve`] would, its refusals included; in particular a second
//! Logon for a session that is already live gets no reply, even if its
//! version or encryption is wrong, while the live session continues.
//!
//! # Limits
//!
//! Reading the Logon and resolving its session are bounded together by one
//! deadline, the registry's logon timeout
//! ([`AcceptorRegistry::with_logon_timeout`]). The Logon is framed under the
//! registry's own ceiling ([`AcceptorRegistry::with_max_message_size`]) with
//! checksum validation and garbled-frame recovery on; a garbled frame is
//! skipped as it is on [`Acceptor::serve`]. Once routed, the socket switches
//! to the session's own codec settings, and the Logon is held to the
//! session's `max_message_size` as well.
//!
//! The registry bounds each connection, not how many there are: capping the
//! connections whose Logon is still being read or routed is the consumer's
//! job, as the accept loop is (see the example).
//!
//! Every session keeps its own sequence numbers, store, heartbeat and
//! settings: the registry only chooses which [`Acceptor`] serves a connection.
//!
//! # Example
//!
//! ```no_run
//! use ironfix_core::types::CompId;
//! use ironfix_engine::application::NoOpApplication;
//! use ironfix_engine::{Acceptor, AcceptorRegistry};
//! use ironfix_session::SessionConfig;
//! use std::sync::Arc;
//! use tokio::net::TcpListener;
//! use tokio::sync::Semaphore;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let application = Arc::new(NoOpApplication);
//! let registry = Arc::new(AcceptorRegistry::new());
//! // One session per member: sender is the venue, target the member it
//! // expects.
//! for member in ["MEMBER_A", "MEMBER_B"] {
//!     let config = SessionConfig::new(CompId::new("VENUE")?, CompId::new(member)?, "FIX.4.4");
//!     registry.register(Acceptor::new(config, Arc::clone(&application)))?;
//! }
//! let listener = TcpListener::bind("127.0.0.1:9876").await?;
//!
//! // The cap on connections still in their Logon handshake is the
//! // consumer's: past it, a new connection is closed at once instead of
//! // holding a socket and a task while it is read and routed.
//! let handshakes = Arc::new(Semaphore::new(64));
//! loop {
//!     let (stream, _) = listener.accept().await?;
//!     let Ok(permit) = Arc::clone(&handshakes).try_acquire_owned() else {
//!         drop(stream);
//!         continue;
//!     };
//!     let registry = Arc::clone(&registry);
//!     tokio::spawn(async move {
//!         let served = registry.serve(stream).await;
//!         // The handshake is over, routed or not: free its place.
//!         drop(permit);
//!         if let Ok(connection) = served {
//!             connection.wait_closed().await;
//!         }
//!     });
//! }
//! # }
//! ```

use crate::acceptor::Acceptor;
use crate::application::{Application, NoOpApplication, SessionId};
use crate::connection::Connection;
use crate::error::EngineError;
use crate::reactor::{HandshakeRead, read_handshake_frame_until};
use crate::stream::SessionStream;
use crate::tls::{DEFAULT_TLS_HANDSHAKE_TIMEOUT, PeerInfo};
use crate::wire::{self, FieldOccurrence};
use async_trait::async_trait;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::CompId;
use ironfix_session::config::{
    MAX_ID_LEN, MAX_MESSAGE_SIZE_LIMIT, MAX_TIMEOUT, MIN_MESSAGE_SIZE_LIMIT,
};
use ironfix_session::{SessionConfig, logon_deadline};
use ironfix_transport::FixCodec;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_util::codec::Framed;

/// Default bound on reading and routing an inbound Logon (10 s, the
/// [`SessionConfig::logon_timeout`] default).
const DEFAULT_LOGON_TIMEOUT: Duration = Duration::from_secs(10);

/// Default ceiling, in bytes, on the Logon frame read before routing (64 KiB).
///
/// The peer is unknown and unauthenticated at that point, so the ceiling is
/// also the most one connection can make the registry buffer before it has
/// been routed anywhere. A Logon is a few hundred bytes; 64 KiB leaves room
/// for credentials in `RawData` (96) and a FIXT `NoMsgTypes` (384) group.
const DEFAULT_MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// How the handshake-read report names a connection before it is routed.
const UNROUTED: &str = "unrouted";

/// Longest prefix of an unroutable identity value that is logged, in bytes.
const LOGGED_PREFIX_LEN: usize = 16;

/// The identity an inbound Logon claims, read from its standard header and
/// bounded before any session is consulted.
///
/// It is stated in the **Logon's own orientation**: [`Self::sender_comp_id`]
/// is the Logon's `SenderCompID` (49), the counterparty, which a session
/// configures as its `target_comp_id`; [`Self::target_comp_id`] is the
/// Logon's `TargetCompID` (56), which a session configures as its
/// `sender_comp_id`. The sub and location IDs are reversed the same way.
///
/// Every value is 1 to [`MAX_ID_LEN`] bytes of printable ASCII and occurs
/// once in the standard header. Nothing in it has been authenticated: it is
/// what the peer claims, and matching CompIDs authenticate nobody.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogonIdentity {
    /// `SenderCompID` (49): the counterparty.
    sender_comp_id: CompId,
    /// `TargetCompID` (56): the session the counterparty asks for.
    target_comp_id: CompId,
    /// `SenderSubID` (50), when the Logon carries one.
    sender_sub_id: Option<String>,
    /// `TargetSubID` (57), when the Logon carries one.
    target_sub_id: Option<String>,
    /// `SenderLocationID` (142), when the Logon carries one.
    sender_location_id: Option<String>,
    /// `TargetLocationID` (143), when the Logon carries one.
    target_location_id: Option<String>,
}

impl LogonIdentity {
    /// The Logon's `SenderCompID` (49): the counterparty, a session's
    /// configured `target_comp_id`.
    #[must_use]
    pub const fn sender_comp_id(&self) -> &CompId {
        &self.sender_comp_id
    }

    /// The Logon's `TargetCompID` (56): a session's configured
    /// `sender_comp_id`.
    #[must_use]
    pub const fn target_comp_id(&self) -> &CompId {
        &self.target_comp_id
    }

    /// The Logon's `SenderSubID` (50), if it carries one: a session's
    /// configured `target_sub_id`.
    #[must_use]
    pub fn sender_sub_id(&self) -> Option<&str> {
        self.sender_sub_id.as_deref()
    }

    /// The Logon's `TargetSubID` (57), if it carries one: a session's
    /// configured `sender_sub_id`.
    #[must_use]
    pub fn target_sub_id(&self) -> Option<&str> {
        self.target_sub_id.as_deref()
    }

    /// The Logon's `SenderLocationID` (142), if it carries one: a session's
    /// configured `target_location_id`.
    #[must_use]
    pub fn sender_location_id(&self) -> Option<&str> {
        self.sender_location_id.as_deref()
    }

    /// The Logon's `TargetLocationID` (143), if it carries one: a session's
    /// configured `sender_location_id`.
    #[must_use]
    pub fn target_location_id(&self) -> Option<&str> {
        self.target_location_id.as_deref()
    }

    /// Reads and bounds the identity of an inbound Logon.
    ///
    /// Pure, and reads no clock (ADR-0002). Each field is taken from the
    /// standard header only and must occur there at most once; 49 and 56 are
    /// required, and every field present must pass [`bounded_value`].
    ///
    /// # Errors
    /// The first field that fails, with what is wrong with it and, when it
    /// has one value, its raw bytes for the caller's truncated log line.
    fn from_logon<'a>(raw: &RawMessage<'a>) -> Result<Self, RoutingRefusal<'a>> {
        let sender_comp_id = required_comp_id(raw, 49)?;
        let target_comp_id = required_comp_id(raw, 56)?;
        Ok(Self {
            sender_comp_id,
            target_comp_id,
            sender_sub_id: optional_value(raw, 50)?,
            target_sub_id: optional_value(raw, 57)?,
            sender_location_id: optional_value(raw, 142)?,
            target_location_id: optional_value(raw, 143)?,
        })
    }

    /// The optional fields with their tags, in a fixed order.
    fn optional(&self) -> [(u32, Option<&str>); 4] {
        [
            (50, self.sender_sub_id()),
            (57, self.target_sub_id()),
            (142, self.sender_location_id()),
            (143, self.target_location_id()),
        ]
    }
}

impl std::fmt::Display for LogonIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "49={} 56={}", self.sender_comp_id, self.target_comp_id)?;
        for (tag, value) in self.optional() {
            if let Some(value) = value {
                write!(f, " {tag}={value}")?;
            }
        }
        Ok(())
    }
}

/// Why a [`SessionLookup`] could not decide whether to admit a session: its
/// directory is unavailable, as opposed to refusing the identity (which is
/// `Ok(None)`).
///
/// The reason is the lookup's own text. It is logged as a warning and
/// returned in [`EngineError::Lookup`]; the lookup never sees the Logon, so
/// it holds no credentials of the peer's, and must not be given any of the
/// lookup's own.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct LookupError {
    /// Why the lookup could not decide.
    reason: String,
}

impl LookupError {
    /// Creates a lookup error with the reason the lookup could not decide.
    ///
    /// # Arguments
    /// * `reason` - Why the lookup could not decide, for the log and the error
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// Returns why the lookup could not decide.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Why an inbound Logon's identity cannot be routed, before it becomes an
/// [`EngineError::UnroutableLogon`].
#[derive(Debug)]
struct RoutingRefusal<'a> {
    /// The identity field that failed.
    tag: u32,
    /// What is wrong with it; never quotes the value.
    detail: String,
    /// The value's raw bytes, for a truncated, escaped log line only.
    value: Option<&'a [u8]>,
}

impl RoutingRefusal<'_> {
    /// Logs the refusal at debug level (any peer can provoke it) with at most
    /// [`LOGGED_PREFIX_LEN`] escaped bytes of the value, and turns it into the
    /// error `serve` returns.
    #[cold]
    #[inline(never)]
    fn into_error(self) -> EngineError {
        let shown = self.value.map(|value| {
            let prefix = value.get(..LOGGED_PREFIX_LEN).unwrap_or(value);
            prefix.escape_ascii().to_string()
        });
        tracing::debug!(
            tag = self.tag,
            detail = %self.detail,
            prefix = shown.as_deref().unwrap_or(""),
            len = self.value.map_or(0, <[u8]>::len),
            "refusing an unroutable Logon without a reply"
        );
        EngineError::UnroutableLogon {
            tag: self.tag,
            detail: self.detail,
        }
    }
}

/// Checks one identity value read from an unvalidated Logon: 1 to
/// [`MAX_ID_LEN`] bytes of printable ASCII (`0x20..=0x7e`), the bound a
/// [`CompId`] and every configured sub and location ID obey.
///
/// # Errors
/// What is wrong with the value, without quoting it.
fn bounded_value(value: &[u8]) -> Result<&str, String> {
    if value.is_empty() {
        return Err("is empty".to_string());
    }
    if value.len() > MAX_ID_LEN {
        return Err(format!(
            "is {} bytes long, above the {MAX_ID_LEN}-byte bound",
            value.len()
        ));
    }
    if let Some((position, byte)) = value
        .iter()
        .enumerate()
        .find(|(_, byte)| !(byte.is_ascii_graphic() || **byte == b' '))
    {
        return Err(format!(
            "carries the byte 0x{byte:02x} at position {position}, outside printable ASCII"
        ));
    }
    // Printable ASCII is UTF-8; this cannot fail and is kept typed.
    std::str::from_utf8(value).map_err(|_| "is not text".to_string())
}

/// Reads one identity field from the standard header: absent is `None`, a
/// single occurrence must be bounded, a repeated one is refused.
///
/// # Errors
/// The field repeated in the header (`SessionRejectReason` 13), or a value
/// that fails [`bounded_value`].
fn header_value<'a>(raw: &RawMessage<'a>, tag: u32) -> Result<Option<&'a str>, RoutingRefusal<'a>> {
    match wire::header_field(raw, tag) {
        FieldOccurrence::Absent => Ok(None),
        FieldOccurrence::Repeated => Err(RoutingRefusal {
            tag,
            detail: "occurs more than once in the standard header".to_string(),
            value: None,
        }),
        FieldOccurrence::Once(value) => {
            bounded_value(value)
                .map(Some)
                .map_err(|detail| RoutingRefusal {
                    tag,
                    detail,
                    value: Some(value),
                })
        }
    }
}

/// Reads a required CompID (49 or 56) from the standard header.
fn required_comp_id<'a>(raw: &RawMessage<'a>, tag: u32) -> Result<CompId, RoutingRefusal<'a>> {
    let Some(text) = header_value(raw, tag)? else {
        return Err(RoutingRefusal {
            tag,
            detail: "is absent from the standard header".to_string(),
            value: None,
        });
    };
    CompId::new(text).map_err(|err| RoutingRefusal {
        tag,
        detail: err.to_string(),
        value: Some(text.as_bytes()),
    })
}

/// Reads an optional identity field (50, 57, 142, 143) from the standard
/// header: absent is `None`, present must be bounded.
fn optional_value<'a>(
    raw: &RawMessage<'a>,
    tag: u32,
) -> Result<Option<String>, RoutingRefusal<'a>> {
    Ok(header_value(raw, tag)?.map(str::to_string))
}

/// The identity a session's counterparty must claim to be routed to it: the
/// session's configuration, reversed into the Logon's orientation.
///
/// An optional field that is `None` here places no requirement on the Logon.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RoutePattern {
    /// Required `SenderCompID` (49): the configured `target_comp_id`.
    sender_comp_id: CompId,
    /// Required `TargetCompID` (56): the configured `sender_comp_id`.
    target_comp_id: CompId,
    /// Required `SenderSubID` (50), when `target_sub_id` is configured.
    sender_sub_id: Option<String>,
    /// Required `TargetSubID` (57), when `sender_sub_id` is configured.
    target_sub_id: Option<String>,
    /// Required `SenderLocationID` (142), when `target_location_id` is
    /// configured.
    sender_location_id: Option<String>,
    /// Required `TargetLocationID` (143), when `sender_location_id` is
    /// configured.
    target_location_id: Option<String>,
}

impl RoutePattern {
    /// The pattern a session with this configuration is routed by.
    fn for_session(config: &SessionConfig) -> Self {
        Self {
            sender_comp_id: config.target_comp_id.clone(),
            target_comp_id: config.sender_comp_id.clone(),
            sender_sub_id: config.target_sub_id.clone(),
            target_sub_id: config.sender_sub_id.clone(),
            sender_location_id: config.target_location_id.clone(),
            target_location_id: config.sender_location_id.clone(),
        }
    }

    /// The bucket the pattern lives in: its (49, 56) pair.
    fn comp_ids(&self) -> (CompId, CompId) {
        (self.sender_comp_id.clone(), self.target_comp_id.clone())
    }

    /// The optional requirements with their tags, in [`LogonIdentity`]'s
    /// order.
    fn optional(&self) -> [(u32, Option<&str>); 4] {
        [
            (50, self.sender_sub_id.as_deref()),
            (57, self.target_sub_id.as_deref()),
            (142, self.sender_location_id.as_deref()),
            (143, self.target_location_id.as_deref()),
        ]
    }

    /// Whether a Logon claiming `identity` is routed by this pattern: the
    /// CompIDs are equal, and every optional field the pattern requires is
    /// carried with the same value.
    fn admits(&self, identity: &LogonIdentity) -> bool {
        self.sender_comp_id == identity.sender_comp_id
            && self.target_comp_id == identity.target_comp_id
            && self.optional().into_iter().zip(identity.optional()).all(
                |((_, required), (_, claimed))| {
                    required.is_none_or(|required| claimed == Some(required))
                },
            )
    }

    /// Whether some Logon would be admitted by both patterns: the CompIDs are
    /// equal and no optional field is required by both with different
    /// values.
    fn overlaps(&self, other: &Self) -> bool {
        self.sender_comp_id == other.sender_comp_id
            && self.target_comp_id == other.target_comp_id
            && self
                .optional()
                .into_iter()
                .zip(other.optional())
                .all(|((_, mine), (_, theirs))| match (mine, theirs) {
                    (Some(mine), Some(theirs)) => mine == theirs,
                    _ => true,
                })
    }
}

impl std::fmt::Display for RoutePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "49={} 56={}", self.sender_comp_id, self.target_comp_id)?;
        for (tag, value) in self.optional() {
            if let Some(value) = value {
                write!(f, " {tag}={value}")?;
            }
        }
        Ok(())
    }
}

/// How a session came to be in the registry, and whether it is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteState {
    /// Registered with [`AcceptorRegistry::register`]: kept for the
    /// registry's lifetime.
    Registered,
    /// Admitted by the lookup, and no handshake has got past `from_admin`
    /// yet: evicted when the last claim on it is released while it is still
    /// in this state.
    Provisional,
    /// Admitted by the lookup, and a handshake got past `from_admin`: kept
    /// for the registry's lifetime.
    Confirmed,
}

/// One session in the registry: the pattern it is routed by, the acceptor
/// that serves it, and whether it is kept.
struct Route<A: Application> {
    /// What a Logon must claim to be routed here.
    pattern: RoutePattern,
    /// The session's acceptor, shared by every connection routed to it, so
    /// its admission slot and owed-reset record are one per session.
    acceptor: Arc<Acceptor<A>>,
    /// Whether the route is kept or still provisional.
    state: RouteState,
    /// Connections routed to the session while it was provisional whose
    /// handshake has not ended yet: one [`ProvisionalClaim`] each. Read and
    /// written only under the write lock, so a release and a new claim never
    /// interleave; a reference count would not do, because a releasing claim
    /// still holds its reference while it decides.
    claims: usize,
}

/// Every session in the registry, and how many the lookup admitted.
struct RouteTable<A: Application> {
    /// Sessions, bucketed by the (49, 56) pair they are routed by. Within a
    /// bucket no two patterns overlap, so a Logon matches at most one route.
    buckets: HashMap<(CompId, CompId), Vec<Route<A>>>,
    /// Lookup-admitted sessions in the table, provisional or confirmed: what
    /// [`AcceptorRegistry::with_max_sessions`] caps.
    from_lookup: usize,
}

impl<A: Application> RouteTable<A> {
    /// An empty table.
    fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            from_lookup: 0,
        }
    }

    /// Every route, in no particular order.
    fn routes(&self) -> impl Iterator<Item = &Route<A>> {
        self.buckets.values().flatten()
    }
}

/// Where a session being inserted comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// [`AcceptorRegistry::register`]: the same pattern twice is refused.
    Registered,
    /// The lookup: the session is provisional, counts toward the cap, and an
    /// equal pattern already present (a lookup that raced this one) is kept
    /// instead.
    Lookup,
}

/// The session a Logon was routed to.
enum Routed<'r, A: Application + 'static> {
    /// A registered or confirmed session: kept whatever this handshake does.
    Kept(Arc<Acceptor<A>>),
    /// A provisional session, with this connection's claim on it.
    Provisional(ProvisionalClaim<'r, A>),
}

impl<A: Application + 'static> Routed<'_, A> {
    /// The routed session's acceptor.
    fn acceptor(&self) -> &Arc<Acceptor<A>> {
        match self {
            Self::Kept(acceptor) => acceptor,
            Self::Provisional(claim) => &claim.acceptor,
        }
    }

    /// Whether this connection holds a claim on a provisional session.
    const fn is_provisional(&self) -> bool {
        matches!(self, Self::Provisional(_))
    }
}

/// A connection's claim on a provisional, lookup-admitted session.
///
/// Taken under the write lock by the step that routed the Logon (the lookup
/// admission, a raced admission, or a later Logon finding the session), and
/// released exactly once when it drops: when the handshake ends, however it
/// ends, a `serve` future dropped mid-handshake included.
struct ProvisionalClaim<'r, A: Application + 'static> {
    /// The registry that holds the session.
    registry: &'r AcceptorRegistry<A>,
    /// The session's acceptor.
    acceptor: Arc<Acceptor<A>>,
    /// Set by the handshake once `from_admin` has accepted the Logon.
    authenticated: AtomicBool,
    /// Whether the claim has been released, so a second release is a no-op.
    released: bool,
}

impl<'r, A: Application + 'static> ProvisionalClaim<'r, A> {
    /// A claim the caller has just counted on the session's route.
    const fn new(registry: &'r AcceptorRegistry<A>, acceptor: Arc<Acceptor<A>>) -> Self {
        Self {
            registry,
            acceptor,
            authenticated: AtomicBool::new(false),
            released: false,
        }
    }

    /// Releases the claim, once: later calls do nothing.
    fn release(&mut self) {
        if std::mem::replace(&mut self.released, true) {
            return;
        }
        self.registry
            .release(&self.acceptor, self.authenticated.load(Ordering::Acquire));
    }
}

impl<A: Application + 'static> Drop for ProvisionalClaim<'_, A> {
    fn drop(&mut self) {
        self.release();
    }
}

/// Resolves sessions an [`AcceptorRegistry`] does not know at startup.
///
/// Asked about an inbound Logon whose identity no session in the registry
/// matches. Return `Ok(Some(acceptor))` with the [`Acceptor`] that serves it
/// to admit the session, `Ok(None)` to refuse the Logon, or a [`LookupError`]
/// when the directory cannot decide (it is unavailable, say). A refusal and
/// an error both close the connection without a reply; they differ in how
/// they are logged and reported ([`EngineError::UnknownSession`] against
/// [`EngineError::Lookup`]).
///
/// The lookup sees the routing identity only, never the Logon: credentials
/// such as `Username` (553) and `Password` (554) are checked by
/// [`Application::from_admin`] once the Logon has been routed, so the lookup
/// cannot leak them and need not handle them.
///
/// The returned acceptor's configuration must route the identity it was
/// asked about (its `target_comp_id` is the Logon's `SenderCompID` (49), its
/// `sender_comp_id` the Logon's `TargetCompID` (56), and any sub or location
/// ID it configures is the one the Logon carries, reversed the same way), it
/// must not overlap a session already in the registry, and its store, if any,
/// must not be one another session uses; otherwise the Logon is refused with
/// [`EngineError::Configuration`]. The call is bounded by the registry's
/// logon timeout.
///
/// # Resource use
///
/// - **When it is called.** Once per Logon whose identity no session in the
///   registry matches, so an unauthenticated peer can make it run once per
///   connection by cycling identities. Keep it cheap (a bounded, in-memory or
///   cached directory), and cap the connections still in their handshake in
///   the accept loop (see the [module documentation](self)).
/// - **What admission costs, and when.** The lookup admits **before**
///   [`Application::from_admin`] has authenticated anyone. An admitted session
///   is provisional while its first handshake runs: it holds one `Acceptor`
///   and whatever the lookup built for it (a store, say), and it counts
///   toward [`AcceptorRegistry::with_max_sessions`].
/// - **How long it lives.** If that handshake ends before `from_admin`
///   accepts the Logon (refused, timed out, or the `serve` future dropped)
///   while no other connection is routed to the session, the session is
///   evicted and everything it held is dropped. Nothing is lost: before
///   authentication the store is never touched. Once a handshake gets past
///   `from_admin`, the session stays for the registry's lifetime, so its
///   admission slot and owed-reset record persist across connections, and the
///   lookup is not asked about it again; it cannot then be revoked, so refuse
///   a revoked member in `from_admin`.
/// - **How many.** Admit only identities from a bounded directory, as the
///   example does, and set [`AcceptorRegistry::with_max_sessions`] to bound
///   the lookup-admitted sessions held at once, provisional and confirmed.
///
/// When two Logons for the same unknown identity are looked up at once, the
/// first admitted session is kept and the other `Acceptor` is dropped, so the
/// two still compete for one admission slot.
///
/// # Example
///
/// ```no_run
/// use async_trait::async_trait;
/// use ironfix_core::types::CompId;
/// use ironfix_engine::application::NoOpApplication;
/// use ironfix_engine::{Acceptor, LogonIdentity, LookupError, SessionLookup};
/// use ironfix_session::SessionConfig;
/// use std::collections::HashSet;
/// use std::sync::Arc;
///
/// /// Admits the members of a fixed directory that ask for this venue, and no
/// /// one else.
/// struct MemberDirectory {
///     venue: CompId,
///     members: HashSet<CompId>,
///     application: Arc<NoOpApplication>,
/// }
///
/// #[async_trait]
/// impl SessionLookup<NoOpApplication> for MemberDirectory {
///     async fn lookup(
///         &self,
///         identity: &LogonIdentity,
///     ) -> Result<Option<Acceptor<NoOpApplication>>, LookupError> {
///         if identity.target_comp_id() != &self.venue
///             || !self.members.contains(identity.sender_comp_id())
///         {
///             return Ok(None);
///         }
///         let config = SessionConfig::new(
///             self.venue.clone(),
///             identity.sender_comp_id().clone(),
///             "FIX.4.4",
///         );
///         Ok(Some(Acceptor::new(config, Arc::clone(&self.application))))
///     }
/// }
/// ```
#[async_trait]
pub trait SessionLookup<A: Application>: Send + Sync {
    /// Resolves the session for `identity`: `Ok(Some(_))` admits it,
    /// `Ok(None)` refuses it.
    ///
    /// # Arguments
    /// * `identity` - The bounded identity the inbound Logon claims
    ///
    /// # Errors
    /// A [`LookupError`] when the lookup cannot decide.
    async fn lookup(&self, identity: &LogonIdentity) -> Result<Option<Acceptor<A>>, LookupError>;
}

/// Server-side FIX engine for many sessions on one listener.
///
/// Holds one [`Acceptor`] per session (each with its own configuration,
/// optional store and settings, all sharing one application type `A`), reads
/// each inbound Logon once, routes it by the identity it claims and runs that
/// session's handshake on it. See the [module documentation](self) for the
/// routing rule and its failure modes.
///
/// Sessions can be registered while connections are being served: the
/// registry is typically wrapped in an [`Arc`] and shared across the tasks
/// serving each connection.
pub struct AcceptorRegistry<A: Application = NoOpApplication> {
    /// Every session in the registry.
    ///
    /// A `std::sync::RwLock`, not `tokio::sync` or `DashMap`: every critical
    /// section is synchronous and short (a lookup, a push, a retain, a claim
    /// counted), no guard is ever held across an `.await`, and `register`,
    /// `Debug` and the drop of a [`ProvisionalClaim`] need the lock outside
    /// any async context.
    routes: RwLock<RouteTable<A>>,
    /// Resolves an identity no session in the registry matches.
    lookup: Option<Arc<dyn SessionLookup<A>>>,
    /// Bound on reading and routing one inbound Logon.
    logon_timeout: Duration,
    /// Ceiling, in bytes, on the Logon frame read before routing.
    max_message_size: usize,
    /// Most lookup-admitted sessions held at once, if capped.
    max_sessions: Option<usize>,
    /// Bound on the TLS handshake of `AcceptorRegistry::serve_tls`.
    tls_handshake_timeout: Duration,
}

/// Written by hand rather than derived: `dyn SessionLookup` is not `Debug`.
impl<A: Application> std::fmt::Debug for AcceptorRegistry<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (sessions, from_lookup) = {
            let routes = self.routes.read().unwrap_or_else(PoisonError::into_inner);
            (routes.routes().count(), routes.from_lookup)
        };
        f.debug_struct("AcceptorRegistry")
            .field("sessions", &sessions)
            .field("from_lookup", &from_lookup)
            .field("lookup", &self.lookup.is_some())
            .field("logon_timeout", &self.logon_timeout)
            .field("max_message_size", &self.max_message_size)
            .field("max_sessions", &self.max_sessions)
            .field("tls_handshake_timeout", &self.tls_handshake_timeout)
            .finish()
    }
}

impl<A: Application + 'static> Default for AcceptorRegistry<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Application + 'static> AcceptorRegistry<A> {
    /// Creates an empty registry with no lookup, a 10 s logon timeout, a
    /// 64 KiB ceiling on the Logon frame and no cap on lookup-admitted
    /// sessions.
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(RouteTable::new()),
            lookup: None,
            logon_timeout: DEFAULT_LOGON_TIMEOUT,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_sessions: None,
            tls_handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
        }
    }

    /// Sets the [`SessionLookup`] asked about identities no session in the
    /// registry matches. Without one, such a Logon is refused.
    ///
    /// # Arguments
    /// * `lookup` - Resolves sessions not known at startup
    #[must_use]
    pub fn with_lookup(mut self, lookup: Arc<dyn SessionLookup<A>>) -> Self {
        self.lookup = Some(lookup);
        self
    }

    /// Caps the sessions a [`SessionLookup`] may add to the registry, held at
    /// once: provisional ones (whose first handshake is still running) and
    /// confirmed ones together (default: no cap). Registered sessions do not
    /// count.
    ///
    /// A lookup admission beyond the cap is refused with
    /// [`EngineError::SessionLimit`], closing the connection without a reply.
    /// An evicted provisional session frees its place. Zero refuses every
    /// lookup admission.
    ///
    /// # Arguments
    /// * `max` - Most lookup-admitted sessions held at once
    #[must_use]
    pub const fn with_max_sessions(mut self, max: usize) -> Self {
        self.max_sessions = Some(max);
        self
    }

    /// Sets the bound on reading an inbound Logon and resolving its session
    /// (default 10 s): one deadline for the wait for an intact Logon and the
    /// [`SessionLookup`] call together. Expiry is
    /// [`EngineError::LogonTimeout`].
    ///
    /// The routed session's own `logon_timeout` does not apply on this path:
    /// its Logon has already been read. The value must be non-zero and at most
    /// [`MAX_TIMEOUT`] (300 s); [`AcceptorRegistry::accept`] and
    /// [`AcceptorRegistry::serve`] refuse to run with any other with
    /// [`EngineError::Configuration`].
    ///
    /// # Arguments
    /// * `timeout` - Maximum duration of the routing phase
    #[must_use]
    pub const fn with_logon_timeout(mut self, timeout: Duration) -> Self {
        self.logon_timeout = timeout;
        self
    }

    /// Sets the ceiling, in bytes, on the Logon frame read before it is routed
    /// (default 64 KiB).
    ///
    /// This is the most an unrouted, unauthenticated connection can make the
    /// registry buffer. A larger frame ends the connection with
    /// [`EngineError::Codec`]. Once routed, the Logon is also held to the
    /// session's own `max_message_size`, which governs every later frame. The
    /// value must be in [`MIN_MESSAGE_SIZE_LIMIT`]..=[`MAX_MESSAGE_SIZE_LIMIT`]
    /// bytes; [`AcceptorRegistry::accept`] and [`AcceptorRegistry::serve`]
    /// refuse to run with any other with [`EngineError::Configuration`].
    ///
    /// # Arguments
    /// * `size` - Largest Logon frame accepted before routing, in bytes
    #[must_use]
    pub const fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Sets the bound on the TLS handshake of `AcceptorRegistry::serve_tls`
    /// (`tls` feature), [`DEFAULT_TLS_HANDSHAKE_TIMEOUT`] by default.
    ///
    /// It starts when `serve_tls` is called and ends with the handshake; the
    /// registry's logon timeout starts after it. Expiry fails the call with
    /// [`EngineError::Tls`] carrying
    /// [`TlsError::HandshakeTimeout`](crate::TlsError::HandshakeTimeout). The
    /// TLS timeout of a registered [`Acceptor`] is not read on this path.
    ///
    /// # Arguments
    /// * `timeout` - Maximum duration of the TLS handshake
    #[must_use]
    pub const fn with_tls_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.tls_handshake_timeout = timeout;
        self
    }

    /// Returns the bound on the TLS handshake of
    /// `AcceptorRegistry::serve_tls`.
    #[must_use]
    pub const fn tls_handshake_timeout(&self) -> Duration {
        self.tls_handshake_timeout
    }

    /// Returns the bound on reading and routing an inbound Logon.
    #[must_use]
    pub const fn logon_timeout(&self) -> Duration {
        self.logon_timeout
    }

    /// Returns the ceiling, in bytes, on the Logon frame read before routing.
    #[must_use]
    pub const fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    /// Returns the cap on lookup-admitted sessions, if one is set.
    #[must_use]
    pub const fn max_sessions(&self) -> Option<usize> {
        self.max_sessions
    }

    /// Registers a session.
    ///
    /// The acceptor carries everything the session needs (configuration,
    /// application, optional store and failure policy, timeouts, initial
    /// sequences) and is served exactly as [`Acceptor::serve`] would serve it.
    /// The session is routed by its configured identity, reversed (see the
    /// [module documentation](self)), and kept for the registry's lifetime.
    ///
    /// # Arguments
    /// * `acceptor` - The acceptor of the session to register
    ///
    /// # Errors
    /// [`EngineError::Config`] or [`EngineError::UnsupportedVersion`] for a
    /// configuration the acceptor would refuse to serve, and
    /// [`EngineError::Configuration`] when the session's identity overlaps a
    /// session already in the registry (a Logon could match both; two
    /// sessions that differ only by `BeginString` do), its [`SessionId`] is
    /// already in the registry, or its store is one another session in the
    /// registry uses: a store belongs to exactly one session.
    pub fn register(&self, acceptor: Acceptor<A>) -> Result<(), EngineError> {
        acceptor.preflight()?;
        let pattern = RoutePattern::for_session(acceptor.config());
        self.insert(pattern, acceptor, Origin::Registered).map(drop)
    }

    /// Returns the identifiers of every session in the registry, provisional
    /// lookup admissions included, in no particular order.
    #[must_use]
    pub fn session_ids(&self) -> Vec<SessionId> {
        self.read_routes()
            .routes()
            .map(|route| route.acceptor.session_id().clone())
            .collect()
    }

    /// Accepts the next inbound connection on `listener` and establishes the
    /// session its Logon is routed to.
    ///
    /// A thin convenience over [`AcceptorRegistry::serve`]. For concurrent
    /// handshakes, run the accept loop yourself and spawn a `serve` per
    /// connection (see the [module documentation](self)). Unusable registry
    /// settings are reported before a connection is taken off the listener.
    ///
    /// # Errors
    /// [`EngineError::Configuration`] for unusable registry settings, before
    /// any connection is taken; [`EngineError::Io`] if the TCP accept fails;
    /// otherwise any error [`AcceptorRegistry::serve`] can produce.
    pub async fn accept(&self, listener: &TcpListener) -> Result<Connection, EngineError> {
        self.settings_check()?;
        let (stream, _addr) = listener.accept().await?;
        self.serve(stream).await
    }

    /// Reads the Logon on an already-accepted [`TcpStream`], routes it to its
    /// session and completes that session's handshake.
    ///
    /// `TCP_NODELAY` is set on the socket before the Logon is read, and the
    /// socket is held by value. For any other kind of stream, see
    /// [`AcceptorRegistry::serve_stream`].
    ///
    /// On success the routed session is Active, exactly as after
    /// [`Acceptor::serve`]: `on_create` and `on_logon` have fired for it, and
    /// the returned [`Connection`] belongs to it.
    ///
    /// A Logon that cannot be routed is closed without a reply, touching no
    /// store and running no [`Application`] callback. Once routed, the
    /// session's handshake answers the Logon as [`Acceptor::serve`] does.
    ///
    /// # Arguments
    /// * `stream` - An accepted TCP connection from a counterparty
    ///
    /// # Errors
    /// Before routing: [`EngineError::Configuration`] for unusable registry
    /// settings; [`EngineError::LogonTimeout`] when no intact Logon arrives,
    /// or the [`SessionLookup`] does not answer, within the registry's logon
    /// timeout; [`EngineError::Closed`] when the peer closes first;
    /// [`EngineError::Codec`] for a frame above the registry's ceiling;
    /// [`EngineError::UnexpectedMessage`] when the first frame is not a
    /// Logon; [`EngineError::UnroutableLogon`] for an identity that fails the
    /// routing bounds; [`EngineError::UnknownSession`] when no session matches
    /// and no lookup admits one; [`EngineError::Lookup`] when the lookup cannot
    /// decide; [`EngineError::SessionLimit`] when the lookup admits a session
    /// beyond [`AcceptorRegistry::with_max_sessions`];
    /// [`EngineError::Configuration`] when a lookup returns a session for
    /// another identity, one that overlaps a session in the registry, or one
    /// sharing another session's store; and [`EngineError::Config`] or
    /// [`EngineError::UnsupportedVersion`] for a looked-up session the
    /// acceptor could not serve. After routing: [`EngineError::Codec`] for a
    /// Logon above the session's `max_message_size`, and every error
    /// [`Acceptor::serve`] documents once its Logon has arrived, among them
    /// [`EngineError::LogonRejected`] for a second Logon for a session already
    /// live.
    pub async fn serve(&self, stream: TcpStream) -> Result<Connection, EngineError> {
        // The only way to a TCP session: it sets TCP_NODELAY.
        self.serve_session_stream(SessionStream::tcp(stream), None)
            .await
    }

    /// Completes a TLS handshake on an accepted TCP connection, then reads
    /// the Logon inside TLS, routes it and completes that session's
    /// handshake, as [`AcceptorRegistry::serve`] does.
    ///
    /// Available with the `tls` feature. `config` is the caller's, as on
    /// [`Acceptor::serve_tls`]: one server configuration for every session of
    /// the registry. The order is: the registry's settings check, the TLS
    /// handshake (bounded by
    /// [`AcceptorRegistry::with_tls_handshake_timeout`]; `TCP_NODELAY` is set
    /// on the socket first), the routing of [`AcceptorRegistry::serve`],
    /// unchanged, and then, for the session the Logon was routed to,
    /// `on_create`, [`Application::authorize_peer`] with the client's
    /// certificate chain, and that session's Logon checks. A client
    /// certificate can therefore be bound to the session its Logon claims. A
    /// lookup-admitted session whose peer is refused is evicted like one
    /// whose Logon `from_admin` refuses. See ADR-0009 (`doc/adr/0009-tls.md`).
    ///
    /// # Errors
    /// Every error [`AcceptorRegistry::serve`] documents, and
    /// [`EngineError::Tls`] when the handshake fails or times out (no callback
    /// runs then), or when `authorize_peer` refuses the client; nothing is
    /// written to a refused client.
    #[cfg(feature = "tls")]
    pub async fn serve_tls(
        &self,
        stream: TcpStream,
        config: Arc<crate::tls::rustls::ServerConfig>,
    ) -> Result<Connection, EngineError> {
        self.settings_check()?;
        let (stream, peer) =
            crate::tls::handshake::accept(stream, config, self.tls_handshake_timeout).await?;
        self.serve_session_stream(SessionStream::erased(stream), Some(&peer))
            .await
    }

    /// Reads the Logon on a byte stream the caller has already accepted,
    /// routes it to its session and completes that session's handshake,
    /// exactly as [`AcceptorRegistry::serve`] does on a [`TcpStream`].
    ///
    /// This is the seam for any transport the engine does not accept itself:
    /// a TLS stream built with the TLS stack of your choice, a Unix socket, a
    /// proxied connection, or an in-memory [`tokio::io::duplex`] pipe. Routing
    /// is unchanged: the same deadline, the same ceiling on the Logon frame,
    /// the same identity bounds and refusals without a reply, and the routed
    /// session's handshake runs as [`Acceptor::serve_stream`] would run it.
    /// Connections over different stream types can be routed to the same
    /// registry. Only `TCP_NODELAY`, which [`AcceptorRegistry::serve`] sets,
    /// is not set: that is the caller's.
    ///
    /// The routed session owns the stream from here on; on an error the
    /// stream is dropped, which closes it. The registry's logon timeout bounds
    /// only what happens from this call on: a TLS handshake, or anything else,
    /// run on the stream before it is not bounded by it and is the caller's to
    /// bound.
    ///
    /// The stream must be a well-behaved [`AsyncRead`]: `poll_read` fills the
    /// `ReadBuf` it is handed and never swaps it for another one. The framing
    /// layer (tokio-util) asserts this, and a stream that breaks it panics the
    /// task reading it (the whole process, under `panic = "abort"`).
    ///
    /// The stream is boxed once, here, and the TCP path of
    /// [`AcceptorRegistry::serve`] is not: it holds its socket by value. Each
    /// outbound frame written in one piece then costs three dynamic calls
    /// (`is_write_vectored`, `poll_write_vectored`, `poll_flush`), and each
    /// read poll one, the `Pending` poll on every wakeup included. Nothing has
    /// measured that cost. Pass the stream's concrete type: a stream that is
    /// already boxed (`Box<dyn ...>`, `Pin<Box<dyn ...>>`) is boxed again, for
    /// two allocations and two vtable hops on every call.
    ///
    /// # Arguments
    /// * `stream` - An accepted byte stream from a counterparty
    ///
    /// # Errors
    /// Every error [`AcceptorRegistry::serve`] documents. A stream that closes
    /// before an intact Logon arrives is [`EngineError::Closed`], or
    /// [`EngineError::Codec`] carrying the I/O error when it closes partway
    /// through a frame or fails.
    pub async fn serve_stream<S>(&self, stream: S) -> Result<Connection, EngineError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.serve_session_stream(SessionStream::erased(stream), None)
            .await
    }

    /// [`AcceptorRegistry::serve_stream`] on a stream whose counterparty the
    /// caller's transport has proved, typically a TLS stream from a TLS stack
    /// of the caller's choice, with the certificates the peer presented.
    ///
    /// Routing is unchanged. Once the Logon is routed, the session runs
    /// [`Application::authorize_peer`] with `peer` after `on_create` and
    /// before the Logon is checked; everything else is
    /// [`AcceptorRegistry::serve_stream`]. The engine trusts `peer` as given:
    /// verifying the chain is the caller's TLS stack's job.
    ///
    /// # Arguments
    /// * `stream` - An accepted byte stream from a counterparty
    /// * `peer` - What the transport proved about the counterparty
    ///
    /// # Errors
    /// Every error [`AcceptorRegistry::serve_stream`] documents, and
    /// [`EngineError::Tls`] carrying
    /// [`TlsError::PeerRejected`](crate::TlsError::PeerRejected) when
    /// `authorize_peer` refuses the peer; nothing is written to the stream
    /// then.
    pub async fn serve_stream_with_peer<S>(
        &self,
        stream: S,
        peer: PeerInfo,
    ) -> Result<Connection, EngineError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.serve_session_stream(SessionStream::erased(stream), Some(&peer))
            .await
    }

    /// [`AcceptorRegistry::serve`] and [`AcceptorRegistry::serve_stream`] on
    /// the connection's stream, TCP or erased.
    ///
    /// # Errors
    /// Every error [`AcceptorRegistry::serve`] documents.
    async fn serve_session_stream(
        &self,
        stream: SessionStream,
        peer: Option<&PeerInfo>,
    ) -> Result<Connection, EngineError> {
        self.settings_check()?;
        // One deadline for the read and the lookup together: the sans-IO
        // core's logon deadline (issue #91 stage 5), on the driver clock. The
        // bound is checked to be at most `MAX_TIMEOUT`, so it cannot
        // overflow; an unschedulable one is still refused.
        let deadline = logon_deadline(crate::reactor::driver_now(), self.logon_timeout)
            .map(Instant::from_std)
            .ok_or_else(|| {
                EngineError::Configuration(format!(
                    "registry logon timeout {:?} cannot be scheduled",
                    self.logon_timeout
                ))
            })?;

        let mut framed = Framed::new(stream, routing_codec(self.max_message_size));

        let logon_frame = match read_handshake_frame_until(&mut framed, deadline, UNROUTED).await {
            HandshakeRead::Frame(frame) => frame,
            HandshakeRead::TimedOut => {
                tracing::debug!("no intact Logon within the registry's logon timeout");
                return Err(EngineError::LogonTimeout(self.logon_timeout));
            }
            HandshakeRead::Closed => return Err(EngineError::Closed),
            HandshakeRead::Codec(err) => return Err(err.into()),
        };

        match self.route(&logon_frame, deadline).await? {
            Routed::Kept(acceptor) => acceptor.serve_logon(framed, logon_frame, None, peer).await,
            // A lookup-admitted session not yet authenticated: whatever ends
            // this handshake, the claim is released when this arm ends (the
            // session kept once `from_admin` accepted a Logon for it, evicted
            // with the last claim otherwise).
            Routed::Provisional(claim) => {
                claim
                    .acceptor
                    .serve_logon(framed, logon_frame, Some(&claim.authenticated), peer)
                    .await
            }
        }
    }

    /// Resolves the session a Logon frame is routed to: one in the registry,
    /// or one the lookup admits before `deadline`.
    ///
    /// # Errors
    /// The routing refusals [`AcceptorRegistry::serve`] documents.
    async fn route(&self, frame: &[u8], deadline: Instant) -> Result<Routed<'_, A>, EngineError> {
        let identity = {
            // Decoded once already by the read, which skips what does not
            // decode; the error is kept typed rather than unwrapped.
            let raw = wire::decode_frame(frame)?;
            if raw.msg_type() != &MsgType::Logon {
                let msg_type: String = raw.msg_type().as_str().chars().take(16).collect();
                tracing::debug!(
                    msg_type = %msg_type,
                    "refusing a connection whose first message is not a Logon, without a reply"
                );
                return Err(EngineError::UnexpectedMessage { msg_type });
            }
            LogonIdentity::from_logon(&raw).map_err(RoutingRefusal::into_error)?
        };

        if let Some(routed) = self.find(&identity) {
            return Ok(routed);
        }

        let Some(lookup) = &self.lookup else {
            tracing::debug!(
                identity = %identity,
                "refusing a Logon for an unknown session without a reply"
            );
            return Err(EngineError::UnknownSession {
                identity: Box::new(identity),
            });
        };
        let resolved = match tokio::time::timeout_at(deadline, lookup.lookup(&identity)).await {
            Err(_) => {
                tracing::warn!(
                    identity = %identity,
                    "the session lookup did not answer within the logon timeout; closing \
                     without a reply"
                );
                return Err(EngineError::LogonTimeout(self.logon_timeout));
            }
            Ok(Err(err)) => {
                tracing::warn!(
                    identity = %identity,
                    error = %err,
                    "the session lookup could not decide; closing without a reply"
                );
                return Err(EngineError::Lookup(err));
            }
            Ok(Ok(None)) => {
                tracing::debug!(
                    identity = %identity,
                    "the session lookup refused the Logon; closing without a reply"
                );
                return Err(EngineError::UnknownSession {
                    identity: Box::new(identity),
                });
            }
            Ok(Ok(Some(acceptor))) => acceptor,
        };
        self.admit_resolved(&identity, resolved).inspect_err(|err| {
            // The cap logs its own refusal; anything else is a session the
            // lookup should not have returned, which is the operator's to fix.
            if !matches!(err, EngineError::SessionLimit { .. }) {
                tracing::warn!(
                    identity = %identity,
                    error = %err,
                    "the session lookup returned a session the registry cannot hold; closing \
                     without a reply"
                );
            }
        })
    }

    /// Adds a session the lookup resolved for `identity`, provisionally, or
    /// returns the session already in the registry for the same identity
    /// (a lookup that raced this one).
    ///
    /// # Errors
    /// [`EngineError::Configuration`] when the acceptor does not route
    /// `identity`, overlaps another session or shares another session's
    /// store; [`EngineError::SessionLimit`] beyond the cap; the acceptor's own
    /// configuration errors.
    fn admit_resolved(
        &self,
        identity: &LogonIdentity,
        acceptor: Acceptor<A>,
    ) -> Result<Routed<'_, A>, EngineError> {
        let pattern = RoutePattern::for_session(acceptor.config());
        if !pattern.admits(identity) {
            return Err(EngineError::Configuration(format!(
                "the session lookup returned session {} (routed by {pattern}) for a Logon \
                 claiming {identity}",
                acceptor.session_id()
            )));
        }
        acceptor.preflight()?;
        let routed = self.insert(pattern, acceptor, Origin::Lookup)?;
        tracing::debug!(
            session = %routed.acceptor().session_id(),
            provisional = routed.is_provisional(),
            "session admitted by the session lookup"
        );
        Ok(routed)
    }

    /// The session in the registry a Logon claiming `identity` is routed to.
    ///
    /// A registered or confirmed session is found under the read lock. A
    /// provisional one is claimed under the write lock, after finding it
    /// again there: a release that would evict it either runs first (the
    /// session is gone and the Logon goes to the lookup) or counts this claim.
    fn find(&self, identity: &LogonIdentity) -> Option<Routed<'_, A>> {
        let key = (
            identity.sender_comp_id.clone(),
            identity.target_comp_id.clone(),
        );
        {
            let routes = self.read_routes();
            let route = routes
                .buckets
                .get(&key)?
                .iter()
                .find(|route| route.pattern.admits(identity))?;
            if route.state != RouteState::Provisional {
                return Some(Routed::Kept(Arc::clone(&route.acceptor)));
            }
        }
        let mut routes = self.write_routes();
        let route = routes
            .buckets
            .get_mut(&key)?
            .iter_mut()
            .find(|route| route.pattern.admits(identity))?;
        if route.state != RouteState::Provisional {
            return Some(Routed::Kept(Arc::clone(&route.acceptor)));
        }
        // Bounded by the connections in flight; cannot overflow, and is still
        // added with a checked call.
        route.claims = route.claims.checked_add(1)?;
        let acceptor = Arc::clone(&route.acceptor);
        drop(routes);
        Some(Routed::Provisional(ProvisionalClaim::new(self, acceptor)))
    }

    /// Adds a session under `pattern`, keeping every bucket free of overlaps
    /// and the registry free of duplicate session identifiers and shared
    /// stores.
    ///
    /// # Errors
    /// [`EngineError::Configuration`] for an overlap (the same pattern
    /// registered twice included), a duplicate [`SessionId`] or a shared
    /// store; [`EngineError::SessionLimit`] for a lookup admission beyond the
    /// cap.
    fn insert(
        &self,
        pattern: RoutePattern,
        acceptor: Acceptor<A>,
        origin: Origin,
    ) -> Result<Routed<'_, A>, EngineError> {
        let key = pattern.comp_ids();
        let store = acceptor.store_address();
        let mut routes = self.write_routes();
        if origin == Origin::Lookup
            && let Some(route) = routes
                .buckets
                .get_mut(&key)
                .and_then(|bucket| bucket.iter_mut().find(|route| route.pattern == pattern))
        {
            // A lookup that raced this one admitted the same session: keep
            // it, and claim it if it is still provisional.
            if route.state != RouteState::Provisional {
                return Ok(Routed::Kept(Arc::clone(&route.acceptor)));
            }
            route.claims = route
                .claims
                .checked_add(1)
                .ok_or(EngineError::SessionLimit { max: usize::MAX })?;
            let acceptor = Arc::clone(&route.acceptor);
            drop(routes);
            return Ok(Routed::Provisional(ProvisionalClaim::new(self, acceptor)));
        }
        if let Some(bucket) = routes.buckets.get(&key) {
            for route in bucket {
                if route.pattern.overlaps(&pattern) {
                    return Err(EngineError::Configuration(format!(
                        "session {} (routed by {pattern}) overlaps the session {} (routed by {}): \
                         a Logon could match both",
                        acceptor.session_id(),
                        route.acceptor.session_id(),
                        route.pattern
                    )));
                }
                if route.acceptor.session_id() == acceptor.session_id() {
                    return Err(EngineError::Configuration(format!(
                        "session {} is already in the registry",
                        acceptor.session_id()
                    )));
                }
            }
        }
        if store.is_some()
            && let Some(route) = routes
                .routes()
                .find(|route| route.acceptor.store_address() == store)
        {
            return Err(EngineError::Configuration(format!(
                "session {} uses the store of the session {}: a store belongs to exactly one \
                 session",
                acceptor.session_id(),
                route.acceptor.session_id()
            )));
        }
        let state = match origin {
            Origin::Registered => RouteState::Registered,
            Origin::Lookup => {
                if let Some(max) = self.max_sessions
                    && routes.from_lookup >= max
                {
                    tracing::warn!(
                        session = %acceptor.session_id(),
                        max,
                        "refusing a lookup admission beyond the session cap, without a reply"
                    );
                    return Err(EngineError::SessionLimit { max });
                }
                // Bounded by the number of sessions in memory: cannot reach
                // `usize::MAX`, and is still added with a checked call.
                routes.from_lookup = routes
                    .from_lookup
                    .checked_add(1)
                    .ok_or(EngineError::SessionLimit { max: usize::MAX })?;
                RouteState::Provisional
            }
        };
        let acceptor = Arc::new(acceptor);
        let provisional = state == RouteState::Provisional;
        routes.buckets.entry(key).or_default().push(Route {
            pattern,
            acceptor: Arc::clone(&acceptor),
            state,
            // The admitting connection's claim.
            claims: usize::from(provisional),
        });
        drop(routes);
        Ok(if provisional {
            Routed::Provisional(ProvisionalClaim::new(self, acceptor))
        } else {
            Routed::Kept(acceptor)
        })
    }

    /// Releases one claim on a provisional session when its handshake ends.
    ///
    /// Under the write lock: the claim is uncounted; the session is confirmed
    /// if this handshake got past `from_admin`; otherwise it is evicted if it
    /// is still provisional and no claim on it remains. Every claim is taken
    /// and released under this lock, so two releases cannot both see the
    /// other's claim and both keep the session. Before authentication the
    /// session's store was never touched, so eviction loses nothing. Called
    /// once per claim, by [`ProvisionalClaim::release`].
    fn release(&self, acceptor: &Arc<Acceptor<A>>, authenticated: bool) {
        let config = acceptor.config();
        let key = (config.target_comp_id.clone(), config.sender_comp_id.clone());
        let mut routes = self.write_routes();
        let table = &mut *routes;
        let Some(bucket) = table.buckets.get_mut(&key) else {
            return;
        };
        let Some(route) = bucket
            .iter_mut()
            .find(|route| Arc::ptr_eq(&route.acceptor, acceptor))
        else {
            return;
        };
        debug_assert!(route.claims > 0, "a claim is released once per claim taken");
        if let Some(remaining) = route.claims.checked_sub(1) {
            route.claims = remaining;
        }
        if route.state != RouteState::Provisional {
            return;
        }
        if authenticated {
            route.state = RouteState::Confirmed;
            tracing::debug!(
                session = %acceptor.session_id(),
                "lookup-admitted session confirmed: a Logon for it was authenticated"
            );
            return;
        }
        if route.claims > 0 {
            return;
        }
        bucket.retain(|route| !Arc::ptr_eq(&route.acceptor, acceptor));
        if bucket.is_empty() {
            table.buckets.remove(&key);
        }
        if let Some(remaining) = table.from_lookup.checked_sub(1) {
            table.from_lookup = remaining;
        }
        tracing::debug!(
            session = %acceptor.session_id(),
            "evicted a lookup-admitted session whose handshakes all ended before authentication"
        );
    }

    /// The registry settings `serve` runs with, checked before a connection
    /// is read.
    ///
    /// # Errors
    /// [`EngineError::Configuration`] naming the setting out of range.
    fn settings_check(&self) -> Result<(), EngineError> {
        if self.logon_timeout.is_zero() || self.logon_timeout > MAX_TIMEOUT {
            return Err(EngineError::Configuration(format!(
                "registry logon timeout {:?} must be non-zero and at most {MAX_TIMEOUT:?}",
                self.logon_timeout
            )));
        }
        if !(MIN_MESSAGE_SIZE_LIMIT..=MAX_MESSAGE_SIZE_LIMIT).contains(&self.max_message_size) {
            return Err(EngineError::Configuration(format!(
                "registry max message size {} bytes must be within \
                 {MIN_MESSAGE_SIZE_LIMIT}..={MAX_MESSAGE_SIZE_LIMIT}",
                self.max_message_size
            )));
        }
        Ok(())
    }

    /// Read access to the routes. A poisoned lock means a holder panicked;
    /// every write is a single push, retain or state change after its checks,
    /// so no half-applied state can be left behind and the guard is
    /// recovered.
    fn read_routes(&self) -> RwLockReadGuard<'_, RouteTable<A>> {
        self.routes.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Write access to the routes; see [`AcceptorRegistry::read_routes`].
    fn write_routes(&self) -> RwLockWriteGuard<'_, RouteTable<A>> {
        self.routes.write().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The codec a connection is framed with until its Logon is routed.
///
/// Garbled-frame recovery is on, as on a session's codec, but with every
/// FIX-family BeginString as a resync anchor: the session, and so its
/// version, is not known yet. Checksums are always validated: the frame comes
/// from an unknown peer.
#[must_use]
fn routing_codec(max_message_size: usize) -> FixCodec {
    FixCodec::new()
        .with_max_message_size(max_message_size)
        .with_checksum_validation(true)
        .with_garbled_recovery(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::NoOpApplication;
    use ironfix_store::{MemoryStore, MessageStore};
    use ironfix_tagvalue::Encoder;

    /// Fails the test with context instead of `.unwrap()` / `.expect()`.
    #[track_caller]
    fn comp_id(value: &str) -> CompId {
        match CompId::new(value) {
            Ok(id) => id,
            Err(err) => panic!("test CompId must be valid: {err}"),
        }
    }

    /// A venue-side session for `member`.
    fn session(member: &str) -> SessionConfig {
        SessionConfig::new(comp_id("VENUE"), comp_id(member), "FIX.4.4")
    }

    fn acceptor(config: SessionConfig) -> Acceptor<NoOpApplication> {
        Acceptor::new(config, Arc::new(NoOpApplication))
    }

    /// Builds a framed message from raw fields in the given order, bypassing
    /// the encoder's header conformance.
    fn frame(fields: &[(u32, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (tag, value) in fields {
            body.extend_from_slice(format!("{tag}=").as_bytes());
            body.extend_from_slice(value);
            body.push(0x01);
        }
        let mut frame = Vec::new();
        frame.extend_from_slice(b"8=FIX.4.4\x01");
        frame.extend_from_slice(format!("9={}\x01", body.len()).as_bytes());
        frame.extend_from_slice(&body);
        let sum: u64 = frame.iter().map(|&byte| u64::from(byte)).sum();
        frame.extend_from_slice(format!("10={:03}\x01", sum % 256).as_bytes());
        frame
    }

    /// A Logon from `sender` to `target` carrying `extra` header fields.
    fn logon(sender: &[u8], target: &[u8], extra: &[(u32, &[u8])]) -> Vec<u8> {
        let mut fields: Vec<(u32, &[u8])> = vec![(35, b"A"), (49, sender), (56, target)];
        fields.extend_from_slice(extra);
        fields.extend_from_slice(&[
            (34, b"1"),
            (52, b"20261018-10:00:00.000"),
            (98, b"0"),
            (108, b"30"),
        ]);
        frame(&fields)
    }

    /// Reads the identity of `frame`, or the refusal's (tag, detail).
    fn identity_of(frame: &[u8]) -> Result<LogonIdentity, (u32, String)> {
        let raw = match wire::decode_frame(frame) {
            Ok(raw) => raw,
            Err(err) => panic!("test frame must decode: {err}"),
        };
        LogonIdentity::from_logon(&raw).map_err(|refusal| (refusal.tag, refusal.detail))
    }

    #[track_caller]
    fn routed(frame: &[u8]) -> LogonIdentity {
        match identity_of(frame) {
            Ok(identity) => identity,
            Err(refusal) => panic!("identity must route: {refusal:?}"),
        }
    }

    /// Admits `config` as the lookup would for `identity`, failing the test
    /// otherwise.
    #[track_caller]
    fn admitted<'r>(
        registry: &'r AcceptorRegistry<NoOpApplication>,
        identity: &LogonIdentity,
        config: SessionConfig,
    ) -> ProvisionalClaim<'r, NoOpApplication> {
        match registry.admit_resolved(identity, acceptor(config)) {
            Ok(Routed::Provisional(claim)) => claim,
            Ok(Routed::Kept(_)) => panic!("a lookup admission must be provisional"),
            Err(err) => panic!("the lookup admission must succeed: {err}"),
        }
    }

    /// Claims the provisional session a Logon claiming `identity` is routed
    /// to, failing the test otherwise.
    #[track_caller]
    fn claimed_again<'r>(
        registry: &'r AcceptorRegistry<NoOpApplication>,
        identity: &LogonIdentity,
    ) -> ProvisionalClaim<'r, NoOpApplication> {
        match registry.find(identity) {
            Some(Routed::Provisional(claim)) => claim,
            Some(Routed::Kept(_)) => panic!("the session must still be provisional"),
            None => panic!("the provisional session must be found"),
        }
    }

    /// The claims counted on the session a Logon claiming `identity` is
    /// routed to, or `None` when there is no such session.
    fn claims_of(
        registry: &AcceptorRegistry<NoOpApplication>,
        identity: &LogonIdentity,
    ) -> Option<usize> {
        registry
            .read_routes()
            .routes()
            .find(|route| route.pattern.admits(identity))
            .map(|route| route.claims)
    }

    #[test]
    fn test_logon_identity_reads_every_header_field() {
        let identity = routed(&logon(
            b"MEMBER",
            b"VENUE",
            &[(50, b"DESK"), (57, b"MM"), (142, b"LON"), (143, b"NYC")],
        ));

        assert_eq!(identity.sender_comp_id().as_str(), "MEMBER");
        assert_eq!(identity.target_comp_id().as_str(), "VENUE");
        assert_eq!(identity.sender_sub_id(), Some("DESK"));
        assert_eq!(identity.target_sub_id(), Some("MM"));
        assert_eq!(identity.sender_location_id(), Some("LON"));
        assert_eq!(identity.target_location_id(), Some("NYC"));
        assert_eq!(
            identity.to_string(),
            "49=MEMBER 56=VENUE 50=DESK 57=MM 142=LON 143=NYC"
        );
    }

    #[test]
    fn test_logon_identity_absent_optional_fields_are_none() {
        let identity = routed(&logon(b"MEMBER", b"VENUE", &[]));

        assert_eq!(identity.sender_sub_id(), None);
        assert_eq!(identity.target_location_id(), None);
        assert_eq!(identity.to_string(), "49=MEMBER 56=VENUE");
    }

    #[test]
    fn test_logon_identity_body_only_comp_id_is_absent() {
        // 98 opens the body; a 49 after it names nobody.
        let frame = frame(&[
            (35, b"A"),
            (56, b"VENUE"),
            (34, b"1"),
            (52, b"20261018-10:00:00.000"),
            (98, b"0"),
            (49, b"MEMBER"),
            (108, b"30"),
        ]);

        match identity_of(&frame) {
            Err((49, detail)) => assert!(detail.contains("absent"), "got {detail}"),
            other => panic!("a body-only 49 must not route: {other:?}"),
        }
    }

    #[test]
    fn test_logon_identity_refuses_a_repeated_field() {
        for tag in [49_u32, 56, 50, 57, 142, 143] {
            let value: &[u8] = match tag {
                49 => b"MEMBER",
                56 => b"VENUE",
                _ => b"X",
            };
            let repeated = [(tag, value), (tag, value)];
            match identity_of(&logon(b"MEMBER", b"VENUE", &repeated)) {
                Err((refused, detail)) => {
                    assert_eq!(refused, tag);
                    assert!(detail.contains("more than once"), "got {detail}");
                }
                Ok(identity) => panic!("a repeated {tag} must not route: {identity}"),
            }
        }
    }

    #[test]
    fn test_logon_identity_refuses_an_over_long_comp_id() {
        let long = "M".repeat(MAX_ID_LEN + 1);
        match identity_of(&logon(long.as_bytes(), b"VENUE", &[])) {
            Err((49, detail)) => {
                assert!(detail.contains("33 bytes"), "got {detail}");
                assert!(!detail.contains(&long), "the value must not be quoted");
            }
            other => panic!("an over-long 49 must not route: {other:?}"),
        }
    }

    #[test]
    fn test_logon_identity_refuses_an_illegal_byte() {
        match identity_of(&logon(b"MEMBER", b"VEN\x80UE", &[])) {
            Err((56, detail)) => assert!(detail.contains("0x80"), "got {detail}"),
            other => panic!("a non-ASCII 56 must not route: {other:?}"),
        }
        match identity_of(&logon(b"MEM\x7fBER", b"VENUE", &[])) {
            Err((49, detail)) => assert!(detail.contains("0x7f"), "got {detail}"),
            other => panic!("a DEL in 49 must not route: {other:?}"),
        }
    }

    #[test]
    fn test_logon_identity_refuses_a_bad_optional_field() {
        let long = "D".repeat(MAX_ID_LEN + 1);
        match identity_of(&logon(b"MEMBER", b"VENUE", &[(50, long.as_bytes())])) {
            Err((50, _)) => {}
            other => panic!("an over-long 50 must not route: {other:?}"),
        }
        match identity_of(&logon(b"MEMBER", b"VENUE", &[(143, b"N\tYC")])) {
            Err((143, detail)) => assert!(detail.contains("0x09"), "got {detail}"),
            other => panic!("a tab in 143 must not route: {other:?}"),
        }
    }

    #[test]
    fn test_bounded_value_accepts_the_bound_and_refuses_empty() {
        let exact = "A".repeat(MAX_ID_LEN);
        assert_eq!(bounded_value(exact.as_bytes()), Ok(exact.as_str()));
        assert_eq!(bounded_value(b"A B=C"), Ok("A B=C"));
        assert_eq!(bounded_value(b""), Err("is empty".to_string()));
    }

    #[test]
    fn test_lookup_error_carries_its_reason() {
        let err = LookupError::new("directory unavailable");
        assert_eq!(err.reason(), "directory unavailable");
        assert_eq!(
            EngineError::from(err).to_string(),
            "session lookup failed: directory unavailable"
        );
    }

    #[test]
    fn test_route_pattern_reverses_the_configuration() {
        let config = session("MEMBER")
            .with_sender_sub_id("VSUB")
            .with_target_sub_id("MSUB");
        let pattern = RoutePattern::for_session(&config);

        assert_eq!(pattern.sender_comp_id.as_str(), "MEMBER");
        assert_eq!(pattern.target_comp_id.as_str(), "VENUE");
        assert_eq!(pattern.sender_sub_id.as_deref(), Some("MSUB"));
        assert_eq!(pattern.target_sub_id.as_deref(), Some("VSUB"));
        assert!(pattern.admits(&routed(&logon(
            b"MEMBER",
            b"VENUE",
            &[(50, b"MSUB"), (57, b"VSUB")],
        ))));
    }

    #[test]
    fn test_route_pattern_unconfigured_fields_place_no_requirement() {
        let pattern = RoutePattern::for_session(&session("MEMBER"));

        assert!(pattern.admits(&routed(&logon(b"MEMBER", b"VENUE", &[]))));
        assert!(pattern.admits(&routed(&logon(
            b"MEMBER",
            b"VENUE",
            &[(50, b"ANY"), (142, b"LON")],
        ))));
        assert!(!pattern.admits(&routed(&logon(b"OTHER", b"VENUE", &[]))));
        assert!(!pattern.admits(&routed(&logon(b"MEMBER", b"OTHER", &[]))));
    }

    #[test]
    fn test_route_pattern_configured_fields_must_be_carried() {
        let mut config = session("MEMBER");
        config.target_location_id = Some("LON".to_string());
        let pattern = RoutePattern::for_session(&config);

        assert!(pattern.admits(&routed(&logon(b"MEMBER", b"VENUE", &[(142, b"LON")]))));
        assert!(!pattern.admits(&routed(&logon(b"MEMBER", b"VENUE", &[(142, b"NYC")]))));
        assert!(!pattern.admits(&routed(&logon(b"MEMBER", b"VENUE", &[]))));
    }

    #[test]
    fn test_route_pattern_overlap() {
        let plain = RoutePattern::for_session(&session("MEMBER"));
        let desk_a = RoutePattern::for_session(&session("MEMBER").with_target_sub_id("A"));
        let desk_b = RoutePattern::for_session(&session("MEMBER").with_target_sub_id("B"));
        let other = RoutePattern::for_session(&session("OTHER"));

        // A catch-all overlaps every refinement of the same pair.
        assert!(plain.overlaps(&desk_a));
        assert!(desk_a.overlaps(&plain));
        assert!(desk_a.overlaps(&desk_a));
        // Two values of the same field are disjoint.
        assert!(!desk_a.overlaps(&desk_b));
        assert!(!plain.overlaps(&other));
    }

    #[test]
    fn test_register_refuses_an_overlapping_session() {
        let registry = AcceptorRegistry::new();
        assert!(registry.register(acceptor(session("MEMBER"))).is_ok());

        match registry.register(acceptor(session("MEMBER").with_target_sub_id("DESK"))) {
            Err(EngineError::Configuration(detail)) => {
                assert!(detail.contains("overlaps"), "got {detail}");
            }
            other => panic!("an overlapping session must be refused: {other:?}"),
        }
        assert_eq!(registry.session_ids().len(), 1);
    }

    #[test]
    fn test_register_refuses_the_same_session_twice() {
        let registry = AcceptorRegistry::new();
        assert!(registry.register(acceptor(session("MEMBER"))).is_ok());

        assert!(matches!(
            registry.register(acceptor(session("MEMBER"))),
            Err(EngineError::Configuration(_))
        ));
    }

    #[test]
    fn test_register_refuses_sessions_differing_only_by_begin_string() {
        // BeginString is not part of the routing key: a FIX.4.2 and a
        // FIX.4.4 session for the same CompIDs would match the same Logons.
        let registry = AcceptorRegistry::new();
        assert!(registry.register(acceptor(session("MEMBER"))).is_ok());

        match registry.register(acceptor(SessionConfig::new(
            comp_id("VENUE"),
            comp_id("MEMBER"),
            "FIX.4.2",
        ))) {
            Err(EngineError::Configuration(detail)) => {
                assert!(detail.contains("overlaps"), "got {detail}");
            }
            other => panic!("a version-only difference must be refused: {other:?}"),
        }
    }

    #[test]
    fn test_register_refuses_a_duplicate_session_id() {
        // Disjoint by location, which a SessionId does not carry: the
        // application could not tell the two sessions apart.
        let mut lon = session("MEMBER");
        lon.target_location_id = Some("LON".to_string());
        let mut nyc = session("MEMBER");
        nyc.target_location_id = Some("NYC".to_string());
        let registry = AcceptorRegistry::new();
        assert!(registry.register(acceptor(lon)).is_ok());

        match registry.register(acceptor(nyc)) {
            Err(EngineError::Configuration(detail)) => {
                assert!(detail.contains("already in the registry"), "got {detail}");
            }
            other => panic!("a duplicate SessionId must be refused: {other:?}"),
        }
    }

    #[test]
    fn test_register_refuses_two_sessions_sharing_a_store() {
        let store: Arc<dyn MessageStore> = Arc::new(MemoryStore::new());
        let registry = AcceptorRegistry::new();
        assert!(
            registry
                .register(acceptor(session("MEMBER_A")).with_store(Arc::clone(&store)))
                .is_ok()
        );

        match registry.register(acceptor(session("MEMBER_B")).with_store(Arc::clone(&store))) {
            Err(EngineError::Configuration(detail)) => {
                assert!(detail.contains("store"), "got {detail}");
            }
            other => panic!("a shared store must be refused: {other:?}"),
        }
        // A store of its own is fine.
        let own: Arc<dyn MessageStore> = Arc::new(MemoryStore::new());
        assert!(
            registry
                .register(acceptor(session("MEMBER_B")).with_store(own))
                .is_ok()
        );
        assert_eq!(registry.session_ids().len(), 2);
    }

    #[test]
    fn test_register_accepts_disjoint_sessions() {
        let registry = AcceptorRegistry::new();
        for config in [
            session("MEMBER_A"),
            session("MEMBER_B"),
            session("MEMBER_C").with_target_sub_id("DESK1"),
            session("MEMBER_C").with_target_sub_id("DESK2"),
        ] {
            assert!(registry.register(acceptor(config)).is_ok());
        }

        assert_eq!(registry.session_ids().len(), 4);
        let found = registry.find(&routed(&logon(b"MEMBER_C", b"VENUE", &[(50, b"DESK2")])));
        match found {
            Some(Routed::Kept(acceptor)) => {
                assert_eq!(acceptor.config().target_sub_id.as_deref(), Some("DESK2"));
            }
            Some(Routed::Provisional(_)) => panic!("a registered session is never provisional"),
            None => panic!("the DESK2 session must be found"),
        }
        assert!(
            registry
                .find(&routed(&logon(b"MEMBER_C", b"VENUE", &[(50, b"DESK3")])))
                .is_none()
        );
    }

    #[test]
    fn test_register_refuses_an_unusable_configuration() {
        let registry = AcceptorRegistry::new();
        let mut config = session("MEMBER");
        config.logon_timeout = Duration::ZERO;
        assert!(matches!(
            registry.register(acceptor(config)),
            Err(EngineError::Config(_))
        ));
        assert!(matches!(
            registry.register(acceptor(SessionConfig::new(
                comp_id("VENUE"),
                comp_id("MEMBER"),
                "FIX.9.9",
            ))),
            Err(EngineError::UnsupportedVersion { .. })
        ));
        assert!(registry.session_ids().is_empty());
    }

    #[test]
    fn test_admit_resolved_refuses_a_session_for_another_identity() {
        let registry = AcceptorRegistry::new();
        let claimed = routed(&logon(b"MEMBER", b"VENUE", &[]));

        match registry.admit_resolved(&claimed, acceptor(session("OTHER"))) {
            Err(EngineError::Configuration(detail)) => {
                assert!(detail.contains("49=MEMBER"), "got {detail}");
            }
            other => panic!(
                "a session for another identity must be refused: {:?}",
                other.err()
            ),
        }
        assert!(registry.session_ids().is_empty());
    }

    #[test]
    fn test_admit_resolved_is_provisional_and_keeps_the_first_admitted_session() {
        let registry = AcceptorRegistry::new();
        let claimed = routed(&logon(b"MEMBER", b"VENUE", &[]));

        let first = admitted(&registry, &claimed, session("MEMBER"));
        let second = admitted(&registry, &claimed, session("MEMBER"));

        // One acceptor, so one admission slot for the session, and one claim
        // per connection on it.
        assert!(Arc::ptr_eq(&first.acceptor, &second.acceptor));
        assert_eq!(claims_of(&registry, &claimed), Some(2));
        assert_eq!(registry.session_ids().len(), 1);
        assert_eq!(registry.read_routes().from_lookup, 1);
    }

    #[test]
    fn test_admit_resolved_refuses_a_shared_store() {
        let store: Arc<dyn MessageStore> = Arc::new(MemoryStore::new());
        let registry = AcceptorRegistry::new();
        assert!(
            registry
                .register(acceptor(session("MEMBER_A")).with_store(Arc::clone(&store)))
                .is_ok()
        );
        let claimed = routed(&logon(b"MEMBER_B", b"VENUE", &[]));

        match registry.admit_resolved(&claimed, acceptor(session("MEMBER_B")).with_store(store)) {
            Err(EngineError::Configuration(detail)) => {
                assert!(detail.contains("store"), "got {detail}");
            }
            other => panic!("a shared store must be refused: {:?}", other.err()),
        }
        assert_eq!(registry.read_routes().from_lookup, 0);
    }

    #[test]
    fn test_release_evicts_an_unauthenticated_provisional_session() {
        let registry = AcceptorRegistry::new();
        let claimed = routed(&logon(b"MEMBER", b"VENUE", &[]));
        let claim = admitted(&registry, &claimed, session("MEMBER"));
        assert_eq!(claims_of(&registry, &claimed), Some(1));

        drop(claim);

        assert!(registry.session_ids().is_empty());
        assert_eq!(registry.read_routes().from_lookup, 0);
    }

    #[test]
    fn test_release_keeps_a_provisional_session_another_connection_claims() {
        let registry = AcceptorRegistry::new();
        let claimed = routed(&logon(b"MEMBER", b"VENUE", &[]));
        let first = admitted(&registry, &claimed, session("MEMBER"));
        let second = claimed_again(&registry, &claimed);
        assert_eq!(claims_of(&registry, &claimed), Some(2));

        // The first connection fails while the second is still routed here.
        drop(first);
        assert_eq!(claims_of(&registry, &claimed), Some(1));

        // Then the second fails too, and nobody is left.
        drop(second);
        assert!(registry.session_ids().is_empty());
    }

    /// The race a reference count could not see: two handshakes end, each
    /// releasing its claim while both still hold a reference to the acceptor
    /// (as a guard does while it releases, and as any other holder might).
    /// Each release sees three references, yet the second one evicts, because
    /// the decision reads the claims counted under the lock.
    #[test]
    fn test_release_evicts_when_the_last_claim_goes_whatever_references_remain() {
        let registry = AcceptorRegistry::new().with_max_sessions(1);
        let claimed = routed(&logon(b"MEMBER", b"VENUE", &[]));
        let mut first = admitted(&registry, &claimed, session("MEMBER"));
        let mut second = claimed_again(&registry, &claimed);
        let held = Arc::clone(&first.acceptor);
        assert_eq!(Arc::strong_count(&held), 4);

        first.release();
        assert_eq!(registry.session_ids().len(), 1);
        second.release();

        assert!(registry.session_ids().is_empty());
        assert_eq!(registry.read_routes().from_lookup, 0);
        // The cap is not exhausted: a new session is admitted.
        let other = routed(&logon(b"OTHER", b"VENUE", &[]));
        let _admitted = admitted(&registry, &other, session("OTHER"));
        assert_eq!(registry.session_ids().len(), 1);
        drop(held);
    }

    #[test]
    fn test_release_is_idempotent_per_claim() {
        let registry = AcceptorRegistry::new();
        let claimed = routed(&logon(b"MEMBER", b"VENUE", &[]));
        let mut first = admitted(&registry, &claimed, session("MEMBER"));
        let second = claimed_again(&registry, &claimed);

        first.release();
        first.release();
        drop(first);

        // Released once: the second claim still keeps the session.
        assert_eq!(claims_of(&registry, &claimed), Some(1));
        assert_eq!(registry.session_ids().len(), 1);
        drop(second);
        assert!(registry.session_ids().is_empty());
    }

    #[test]
    fn test_release_confirms_an_authenticated_session_for_good() {
        let registry = AcceptorRegistry::new();
        let claimed = routed(&logon(b"MEMBER", b"VENUE", &[]));
        let first = admitted(&registry, &claimed, session("MEMBER"));
        let second = claimed_again(&registry, &claimed);

        // The second handshake is authenticated and ends; the first one then
        // fails, the last claim to go, and the session stays.
        second.authenticated.store(true, Ordering::Release);
        drop(second);
        drop(first);

        assert_eq!(registry.session_ids().len(), 1);
        assert_eq!(claims_of(&registry, &claimed), Some(0));
        match registry.find(&claimed) {
            Some(Routed::Kept(_)) => {}
            Some(Routed::Provisional(_)) => panic!("a confirmed session is kept"),
            None => panic!("the confirmed session must stay"),
        }
        assert_eq!(registry.read_routes().from_lookup, 1);
    }

    #[test]
    fn test_registered_session_is_never_claimed() {
        let registry = AcceptorRegistry::new();
        assert!(registry.register(acceptor(session("MEMBER"))).is_ok());
        let claimed = routed(&logon(b"MEMBER", b"VENUE", &[]));

        assert!(matches!(registry.find(&claimed), Some(Routed::Kept(_))));
        assert_eq!(claims_of(&registry, &claimed), Some(0));
        assert_eq!(registry.session_ids().len(), 1);
    }

    #[test]
    fn test_max_sessions_caps_lookup_admissions_only() {
        let registry = AcceptorRegistry::new().with_max_sessions(1);
        assert_eq!(registry.max_sessions(), Some(1));
        // Registered sessions do not count.
        assert!(registry.register(acceptor(session("STATIC"))).is_ok());
        let first = routed(&logon(b"MEMBER_A", b"VENUE", &[]));
        let second = routed(&logon(b"MEMBER_B", b"VENUE", &[]));
        let held = admitted(&registry, &first, session("MEMBER_A"));

        match registry.admit_resolved(&second, acceptor(session("MEMBER_B"))) {
            Err(EngineError::SessionLimit { max }) => assert_eq!(max, 1),
            other => panic!("the cap must refuse a second admission: {:?}", other.err()),
        }
        // The same identity again is the session already held, not a new one.
        assert!(
            registry
                .admit_resolved(&first, acceptor(session("MEMBER_A")))
                .is_ok()
        );

        // An eviction frees the place.
        drop(held);
        let _admitted = admitted(&registry, &second, session("MEMBER_B"));
        assert_eq!(registry.session_ids().len(), 2);
    }

    #[test]
    fn test_max_sessions_zero_refuses_every_lookup_admission() {
        let registry = AcceptorRegistry::new().with_max_sessions(0);
        let claimed = routed(&logon(b"MEMBER", b"VENUE", &[]));

        assert!(matches!(
            registry.admit_resolved(&claimed, acceptor(session("MEMBER"))),
            Err(EngineError::SessionLimit { max: 0 })
        ));
    }

    #[test]
    fn test_settings_check_refuses_out_of_range_settings() {
        let zero: AcceptorRegistry = AcceptorRegistry::new().with_logon_timeout(Duration::ZERO);
        assert!(matches!(
            zero.settings_check(),
            Err(EngineError::Configuration(_))
        ));
        let long: AcceptorRegistry =
            AcceptorRegistry::new().with_logon_timeout(MAX_TIMEOUT + Duration::from_secs(1));
        assert!(matches!(
            long.settings_check(),
            Err(EngineError::Configuration(_))
        ));
        for size in [MIN_MESSAGE_SIZE_LIMIT - 1, MAX_MESSAGE_SIZE_LIMIT + 1] {
            let registry: AcceptorRegistry = AcceptorRegistry::new().with_max_message_size(size);
            match registry.settings_check() {
                Err(EngineError::Configuration(detail)) => {
                    assert!(detail.contains("max message size"), "got {detail}");
                }
                other => panic!("size {size} must be refused: {other:?}"),
            }
        }
    }

    #[test]
    fn test_settings_check_accepts_the_defaults_and_the_bounds() {
        let registry: AcceptorRegistry = AcceptorRegistry::new();
        assert!(registry.settings_check().is_ok());
        assert_eq!(registry.logon_timeout(), DEFAULT_LOGON_TIMEOUT);
        assert_eq!(registry.max_message_size(), DEFAULT_MAX_MESSAGE_SIZE);
        assert_eq!(registry.max_sessions(), None);
        let bounds: AcceptorRegistry = AcceptorRegistry::new()
            .with_logon_timeout(MAX_TIMEOUT)
            .with_max_message_size(MIN_MESSAGE_SIZE_LIMIT);
        assert!(bounds.settings_check().is_ok());
    }

    #[test]
    fn test_registry_debug_counts_sessions_without_printing_them() {
        let registry = AcceptorRegistry::new();
        assert!(registry.register(acceptor(session("MEMBER"))).is_ok());
        let shown = format!("{registry:?}");
        assert!(shown.contains("sessions: 1"), "got {shown}");
        assert!(shown.contains("lookup: false"), "got {shown}");
        assert!(!shown.contains("MEMBER"), "got {shown}");
    }

    #[test]
    fn test_encoder_built_logon_routes() {
        // The same frame shape a real initiator sends.
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "A");
        encoder.put_str(49, "MEMBER");
        encoder.put_str(56, "VENUE");
        encoder.put_uint(34, 1);
        encoder.put_str(52, "20261018-10:00:00.000");
        encoder.put_uint(98, 0);
        encoder.put_uint(108, 30);
        let mut bytes = bytes::BytesMut::new();
        if let Err(err) = encoder.finish_into(&mut bytes) {
            panic!("logon must encode: {err}");
        }
        let identity = routed(&bytes);
        assert_eq!(identity.to_string(), "49=MEMBER 56=VENUE");
    }
}
