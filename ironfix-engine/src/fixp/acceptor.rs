/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! The FIXP server entry point: accept, answer Negotiate and Establish.

use crate::fixp::application::FixpApplication;
use crate::fixp::connection::FixpConnection;
use crate::fixp::driver::{Driver, DriverSettings, Handshake, SessionRegistry};
use crate::fixp::error::FixpEngineError;
use crate::fixp::{DEFAULT_RETRANSMIT_CAPACITY, DEFAULT_WRITE_TIMEOUT};
use crate::stream::SessionStream;
use ironfix_core::Timestamp;
use ironfix_fixp::{ClockAnchor, FixpConfig, FixpServer, SessionId};
use ironfix_sofh::SofhCodec;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

/// The server side of FIXP sessions (FIXP v1.1 sections 4.2 and 4.3): one
/// session per transport, each in its own driver task.
///
/// The application decides every Negotiate and Establish
/// ([`FixpApplication::on_negotiate`],
/// [`FixpApplication::on_establish`]). The acceptor itself refuses, with
/// NegotiationReject `DuplicateId`, a Negotiate naming a session live on
/// another of its transports or finalized (sections 3.4.1 and 6.3); it
/// remembers finalized identifiers in memory for its own lifetime. A session
/// whose transport closes without finalization is forgotten: re-establishing
/// it on a new transport is not supported yet, and the core refuses such an
/// Establish with `Unnegotiated`.
///
/// Cloning shares the application and the registry of sessions.
pub struct FixpAcceptor<A: FixpApplication> {
    app: Arc<A>,
    config: FixpConfig,
    settings: DriverSettings,
    registry: Arc<SessionRegistry>,
}

impl<A: FixpApplication> Clone for FixpAcceptor<A> {
    fn clone(&self) -> Self {
        Self {
            app: Arc::clone(&self.app),
            config: self.config.clone(),
            settings: self.settings,
            registry: Arc::clone(&self.registry),
        }
    }
}

impl<A: FixpApplication> std::fmt::Debug for FixpAcceptor<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixpAcceptor").finish_non_exhaustive()
    }
}

impl<A: FixpApplication> FixpAcceptor<A> {
    /// An acceptor running `app` with `config` on every session.
    #[must_use]
    pub fn new(app: A, config: FixpConfig) -> Self {
        Self {
            app: Arc::new(app),
            config,
            settings: DriverSettings {
                max_message_size: SofhCodec::DEFAULT_MAX_MESSAGE_SIZE,
                retransmit_capacity: DEFAULT_RETRANSMIT_CAPACITY,
                write_timeout: DEFAULT_WRITE_TIMEOUT,
            },
            registry: Arc::new(SessionRegistry::default()),
        }
    }

    /// How many sent application messages each session keeps, on a
    /// Recoverable flow, to answer a RetransmitRequest (default
    /// [`DEFAULT_RETRANSMIT_CAPACITY`]).
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

    /// `true` once a session `session_id` of this acceptor was finalized
    /// (section 4.7.2).
    #[must_use]
    pub fn is_finalized(&self, session_id: SessionId) -> bool {
        self.registry.is_finalized(session_id)
    }

    /// Accepts connections on `listener` until accepting fails, running each
    /// in its own driver task (with `TCP_NODELAY`). Established sessions
    /// reach the application through [`FixpApplication::on_established`].
    ///
    /// Each driver task ends when its transport closes, and every handshake
    /// step is bounded by the configuration's handshake timeout.
    ///
    /// # Errors
    /// [`FixpEngineError::Io`] when `accept` fails.
    pub async fn serve(&self, listener: TcpListener) -> Result<(), FixpEngineError> {
        loop {
            let (stream, peer) = listener.accept().await?;
            tracing::debug!(%peer, "fixp transport accepted");
            let handshake = self.spawn(SessionStream::tcp(stream));
            // The driver task owns the session and ends with its transport;
            // this one only logs how the handshake went, and ends with it.
            tokio::spawn(async move {
                match handshake.await {
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => tracing::info!(%peer, %error, "fixp handshake failed"),
                    Err(_) => tracing::debug!(%peer, "fixp driver ended before the handshake"),
                }
            });
        }
    }

    /// Runs one session on a stream the caller accepted (a TLS stream, an
    /// in-memory duplex, any `AsyncRead + AsyncWrite`), returning once it is
    /// established.
    ///
    /// # Errors
    /// [`FixpEngineError::HandshakeTimedOut`], the application's refusal as
    /// [`FixpEngineError::EstablishmentRejected`], and
    /// [`FixpEngineError::HandshakeFailed`] or a transport error when the
    /// transport ends first.
    pub async fn accept_stream<S>(&self, stream: S) -> Result<FixpConnection, FixpEngineError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.spawn(SessionStream::erased(stream))
            .await
            .map_err(|_| FixpEngineError::Closed)?
    }

    fn spawn(&self, stream: SessionStream) -> Handshake {
        let now = tokio::time::Instant::now().into_std();
        let clock = ClockAnchor::new(now, Timestamp::now());
        let server = FixpServer::new(self.config.clone(), clock, now);
        Driver::spawn_server(
            server,
            Arc::clone(&self.registry),
            stream,
            Arc::clone(&self.app),
            self.settings,
        )
    }
}
