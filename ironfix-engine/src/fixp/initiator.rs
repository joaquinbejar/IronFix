/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! The FIXP client entry point: dial, negotiate, establish.

use crate::fixp::application::FixpApplication;
use crate::fixp::connection::FixpConnection;
use crate::fixp::driver::{Driver, DriverSettings};
use crate::fixp::error::FixpEngineError;
use crate::fixp::{DEFAULT_RETRANSMIT_CAPACITY, DEFAULT_WRITE_TIMEOUT};
use crate::stream::SessionStream;
use ironfix_core::Timestamp;
use ironfix_fixp::{ClockAnchor, Credentials, FixpClient, FixpConfig, FlowType, SessionId};
use ironfix_sofh::SofhCodec;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs};

/// Default bound on the TCP connect of [`FixpInitiator::connect`].
pub const DEFAULT_FIXP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The client side of a FIXP session (FIXP v1.1 sections 4.2 and 4.3):
/// opens a transport, sends Negotiate, then Establish, and returns a
/// [`FixpConnection`] once the EstablishmentAck arrives.
///
/// It is consumed by [`connect`](Self::connect) or
/// [`connect_stream`](Self::connect_stream): a session identifier is never
/// negotiated twice (section 3.4.1), and re-establishing an unbound session
/// on a new transport is not driven by the engine yet.
pub struct FixpInitiator<A: FixpApplication> {
    app: Arc<A>,
    config: FixpConfig,
    session_id: SessionId,
    flow: FlowType,
    credentials: Option<Credentials>,
    connect_timeout: Duration,
    settings: DriverSettings,
}

impl<A: FixpApplication> std::fmt::Debug for FixpInitiator<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Credentials` prints its length only.
        f.debug_struct("FixpInitiator")
            .field("session_id", &self.session_id)
            .field("flow", &self.flow)
            .field("credentials", &self.credentials)
            .field("connect_timeout", &self.connect_timeout)
            .finish_non_exhaustive()
    }
}

impl<A: FixpApplication> FixpInitiator<A> {
    /// A client for session `session_id`, sending on a `flow` flow.
    ///
    /// `session_id` should be a fresh RFC 4122 version 4 UUID (section
    /// 3.4.1); the engine reads no entropy to make one.
    #[must_use]
    pub fn new(app: A, config: FixpConfig, session_id: SessionId, flow: FlowType) -> Self {
        Self {
            app: Arc::new(app),
            config,
            session_id,
            flow,
            credentials: None,
            connect_timeout: DEFAULT_FIXP_CONNECT_TIMEOUT,
            settings: DriverSettings {
                max_message_size: SofhCodec::DEFAULT_MAX_MESSAGE_SIZE,
                retransmit_capacity: DEFAULT_RETRANSMIT_CAPACITY,
                write_timeout: DEFAULT_WRITE_TIMEOUT,
            },
        }
    }

    /// Credentials sent in Negotiate and every Establish. Never logged.
    #[must_use]
    pub fn with_credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Bound on the TCP connect of [`connect`](Self::connect) (default
    /// [`DEFAULT_FIXP_CONNECT_TIMEOUT`]).
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// How many sent application messages are kept, on a Recoverable flow,
    /// to answer a RetransmitRequest (default
    /// [`DEFAULT_RETRANSMIT_CAPACITY`]). A request for one no longer kept
    /// is refused with RetransmitReject `OutOfRange` (section 4.6.2.3).
    #[must_use]
    pub const fn with_retransmit_capacity(mut self, capacity: usize) -> Self {
        self.settings.retransmit_capacity = capacity;
        self
    }

    /// Largest SOFH `Message_Length`, header included, read or written
    /// (default 1 MiB).
    #[must_use]
    pub const fn with_max_message_size(mut self, size: u32) -> Self {
        self.settings.max_message_size = size;
        self
    }

    /// Bound on each write and flush (default [`DEFAULT_WRITE_TIMEOUT`]).
    #[must_use]
    pub const fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.settings.write_timeout = timeout;
        self
    }

    /// Dials `addr` over TCP (with `TCP_NODELAY`) and runs the session on it.
    ///
    /// # Errors
    /// [`FixpEngineError::ConnectTimeout`] or [`FixpEngineError::Io`] for
    /// the dial, then everything [`connect_stream`](Self::connect_stream)
    /// returns.
    pub async fn connect(
        self,
        addr: impl ToSocketAddrs,
    ) -> Result<FixpConnection, FixpEngineError> {
        let stream = tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| FixpEngineError::ConnectTimeout(self.connect_timeout))??;
        self.run(SessionStream::tcp(stream)).await
    }

    /// Runs the session on a stream the caller opened: a TLS stream (for
    /// instance a `tokio_rustls` client stream), an in-memory duplex, any
    /// `AsyncRead + AsyncWrite`.
    ///
    /// Returns once the session is established. The handshake is bounded by
    /// the configuration's handshake timeout.
    ///
    /// # Errors
    /// [`FixpEngineError::NegotiationRejected`],
    /// [`FixpEngineError::EstablishmentRejected`],
    /// [`FixpEngineError::HandshakeTimedOut`], and
    /// [`FixpEngineError::HandshakeFailed`] or a transport error when the
    /// transport ends first.
    pub async fn connect_stream<S>(self, stream: S) -> Result<FixpConnection, FixpEngineError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.run(SessionStream::erased(stream)).await
    }

    async fn run(self, stream: SessionStream) -> Result<FixpConnection, FixpEngineError> {
        let now = tokio::time::Instant::now().into_std();
        let clock = ClockAnchor::new(now, Timestamp::now());
        let client = FixpClient::new(
            self.config,
            clock,
            self.session_id,
            self.flow,
            self.credentials,
        );
        let handshake = Driver::spawn_client(client, stream, self.app, self.settings);
        handshake.await.map_err(|_| FixpEngineError::Closed)?
    }
}
