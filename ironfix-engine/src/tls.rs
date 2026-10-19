/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! TLS: who the counterparty proved to be, and how a TLS failure is reported.
//!
//! FIX over TLS is plain FIX framing inside the TLS stream: nothing on the
//! wire changes, and `EncryptMethod` (98) stays 0. What TLS adds is a
//! counterparty identity the Logon cannot fake: the end-entity certificate
//! the TLS layer verified. This module carries the certificates the peer
//! presented to the application as a [`PeerInfo`] through
//! [`Application::authorize_peer`]; only the first of them is verified (see
//! [`PeerInfo`]).
//!
//! # Always compiled
//!
//! [`PeerInfo`], [`TlsError`] and [`TlsFailure`] carry no rustls type, so they
//! exist with the `tls` feature off as well: a caller that runs a TLS stack of
//! its own hands the chain it verified to
//! [`Initiator::establish_with_peer`](crate::Initiator::establish_with_peer),
//! [`Acceptor::serve_stream_with_peer`](crate::Acceptor::serve_stream_with_peer)
//! or
//! [`AcceptorRegistry::serve_stream_with_peer`](crate::AcceptorRegistry::serve_stream_with_peer),
//! and the [`Application`] trait has the same methods
//! whichever features are on.
//!
//! # The `tls` feature
//!
//! With the feature on, the engines run the TLS handshake themselves over
//! rustls, through tokio-rustls:
//! `Initiator::connect_tls`,
//! `Acceptor::serve_tls` and
//! `AcceptorRegistry::serve_tls`. The
//! caller supplies the `rustls::ClientConfig` or `rustls::ServerConfig`, and
//! with it the crypto provider, the protocol versions, the cipher suites, the
//! roots it trusts and, on the acceptor, whether a client certificate is
//! required (mutual TLS). IronFix enables no provider of its own; see ADR-0009
//! (`doc/adr/0009-tls.md`). The rustls version the engine is built against is
//! re-exported as `ironfix_engine::tls::rustls`, so a caller builds its
//! configuration against the same one.
//!
//! The handshake runs under its own timeout (`with_tls_handshake_timeout` on
//! each engine, [`DEFAULT_TLS_HANDSHAKE_TIMEOUT`] by default), before and
//! separately from the logon timeout, which starts once the handshake is done.
//!
//! # What is never logged
//!
//! A TLS failure is logged and reported by its rustls error text, which names
//! the failure (an unknown issuer, an expired certificate, a protocol alert)
//! and carries no key material. Certificates are never logged. The Logon that
//! follows the handshake is handled exactly as on any other transport:
//! `Password` (554), `NewPassword` (925) and `RawData` (96) never reach a log
//! line.

use crate::application::{Application, SessionId};
use crate::error::EngineError;
use bytes::Bytes;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "tls")]
pub use tokio_rustls::rustls;

/// The TLS handshake timeout an engine starts with: 10 seconds.
pub const DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The certificates the counterparty presented in the TLS handshake,
/// end-entity certificate first, each one DER-encoded, exactly as it sent
/// them.
///
/// Handed to [`Application::authorize_peer`] before the Logon exchange, so
/// an application can bind a certificate to the session (for instance,
/// require that the client certificate names the session's
/// `TargetCompID`). IronFix does not parse the certificates.
///
/// # What is verified, and what is not
///
/// The TLS layer verifies the **end-entity certificate**
/// ([`PeerInfo::end_entity_certificate`], the first one) against the
/// configured roots and the peer's proof that it holds the matching key. The
/// rest of [`PeerInfo::certificate_chain`] is metadata the peer presented: it
/// may contain certificates that took no part in that verification,
/// unrelated ones included, issued by anyone. A certificate after the first
/// proves neither a verified issuer nor an identity, so a binding of a
/// certificate to a CompID must use the end-entity certificate, under the
/// verification policy of the TLS configuration, and treat every other entry
/// as untrusted unless the application validates it separately.
///
/// Through the `*_with_peer` entry points the engine verifies nothing: it
/// passes on what the caller's TLS stack handed over.
///
/// The chain is empty when the counterparty presented no certificate: a
/// client on a server that does not ask for one.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct PeerInfo {
    /// The DER-encoded certificates, end-entity first.
    certificates: Arc<[Bytes]>,
}

impl PeerInfo {
    /// A peer that presented `certificates`, end-entity first, each one
    /// DER-encoded.
    ///
    /// For a caller that runs its own TLS stack and hands the chain the peer
    /// presented to an `*_with_peer` entry point; whatever that stack
    /// verified, the engine verifies nothing more.
    #[must_use]
    pub fn new(certificates: impl IntoIterator<Item = Bytes>) -> Self {
        Self {
            certificates: certificates.into_iter().collect(),
        }
    }

    /// The certificates the counterparty presented, end-entity first, each
    /// one DER-encoded. Empty when it presented none.
    ///
    /// Only the first entry is verified by the TLS layer; the others are
    /// untrusted metadata (see [`PeerInfo`]).
    #[must_use]
    pub fn certificate_chain(&self) -> &[Bytes] {
        &self.certificates
    }

    /// The counterparty's own (end-entity) certificate, DER-encoded, if it
    /// presented one: the one certificate the TLS layer verified against the
    /// configured roots, and the one to bind to a CompID.
    #[must_use]
    pub fn end_entity_certificate(&self) -> Option<&Bytes> {
        self.certificates.first()
    }

    /// Whether the counterparty presented no certificate.
    #[must_use]
    pub fn is_anonymous(&self) -> bool {
        self.certificates.is_empty()
    }
}

/// Prints the chain's length only: a certificate is public, but a log line
/// gains nothing from kilobytes of DER.
impl fmt::Debug for PeerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerInfo")
            .field("certificates", &self.certificates.len())
            .finish()
    }
}

/// Which TLS step failed: the structured part of a [`TlsError`], and what
/// [`CloseReason::Tls`](crate::CloseReason::Tls) carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum TlsFailure {
    /// The TLS handshake failed: an untrusted or expired certificate, a
    /// missing or refused client certificate, no common protocol version or
    /// cipher suite, an invalid server name, a peer that is not speaking TLS,
    /// or a transport failure during the handshake.
    Handshake,
    /// The TLS handshake did not complete within the TLS handshake timeout.
    HandshakeTimeout,
    /// The handshake succeeded but
    /// [`Application::authorize_peer`]
    /// refused the counterparty.
    PeerRejected,
}

impl fmt::Display for TlsFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Handshake => "TLS handshake failed",
            Self::HandshakeTimeout => "TLS handshake timed out",
            Self::PeerRejected => "TLS peer refused by the application",
        })
    }
}

/// A TLS failure, reported as [`EngineError::Tls`].
///
/// Its text never carries key material or a certificate: a handshake failure
/// keeps rustls' description of it, which names the problem only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// The TLS handshake failed. See [`TlsFailure::Handshake`].
    #[error("tls handshake failed: {detail}")]
    #[non_exhaustive]
    Handshake {
        /// The I/O error kind the handshake failed with.
        kind: std::io::ErrorKind,
        /// The TLS stack's description of the failure.
        detail: String,
    },
    /// The TLS handshake did not complete within the timeout.
    #[error("tls handshake timed out after {0:?}")]
    HandshakeTimeout(Duration),
    /// [`Application::authorize_peer`]
    /// refused the counterparty. Nothing was written to it: no Logon, no
    /// Logout.
    #[error("tls peer refused: {reason}")]
    #[non_exhaustive]
    PeerRejected {
        /// The `text` of the application's
        /// [`RejectReason`](crate::RejectReason).
        reason: String,
    },
}

impl TlsError {
    /// Which TLS step failed.
    #[must_use]
    pub const fn failure(&self) -> TlsFailure {
        match self {
            Self::Handshake { .. } => TlsFailure::Handshake,
            Self::HandshakeTimeout(_) => TlsFailure::HandshakeTimeout,
            Self::PeerRejected { .. } => TlsFailure::PeerRejected,
        }
    }

    /// A handshake failure, from the I/O error the TLS stack returned.
    #[cfg(feature = "tls")]
    #[must_use]
    pub(crate) fn handshake(err: &std::io::Error) -> Self {
        Self::Handshake {
            kind: err.kind(),
            detail: err.to_string(),
        }
    }
}

/// Runs [`Application::authorize_peer`] for a session whose transport proved
/// `peer`, before anything is written to it.
///
/// # Errors
/// [`EngineError::Tls`] with [`TlsError::PeerRejected`] when the application
/// refuses the peer.
pub(crate) async fn authorize<A: Application + ?Sized>(
    application: &A,
    session_id: &SessionId,
    peer: &PeerInfo,
) -> Result<(), EngineError> {
    match application.authorize_peer(session_id, peer).await {
        Ok(()) => Ok(()),
        Err(reason) => {
            tracing::warn!(
                session = %session_id,
                certificates = peer.certificate_chain().len(),
                reason = %reason.text,
                "the application refused the TLS peer; closing without a reply"
            );
            Err(EngineError::Tls(TlsError::PeerRejected {
                reason: reason.text,
            }))
        }
    }
}

/// The TLS handshakes the engines run with the `tls` feature on.
#[cfg(feature = "tls")]
pub(crate) mod handshake {
    use super::{PeerInfo, TlsError};
    use bytes::Bytes;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
    use tokio_rustls::rustls::{ClientConfig, ServerConfig};
    use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};

    /// The chain a completed handshake verified, copied out of the TLS
    /// connection.
    fn peer_info(certificates: Option<&[CertificateDer<'_>]>) -> PeerInfo {
        PeerInfo::new(
            certificates
                .unwrap_or_default()
                .iter()
                .map(|cert| Bytes::copy_from_slice(cert.as_ref())),
        )
    }

    /// Logs a handshake failure by its rustls description only.
    fn log_failure(role: &'static str, err: &TlsError) {
        tracing::warn!(role, error = %err, "TLS handshake failed");
    }

    /// The client half of the handshake on a dialled socket, bounded by
    /// `limit`. Sets `TCP_NODELAY` on the socket first, as the TCP path does.
    pub(crate) async fn connect(
        stream: TcpStream,
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
        limit: Duration,
    ) -> Result<(client::TlsStream<TcpStream>, PeerInfo), TlsError> {
        let _ = stream.set_nodelay(true);
        let connector = TlsConnector::from(config);
        let result = match timeout(limit, connector.connect(server_name, stream)).await {
            Err(_) => Err(TlsError::HandshakeTimeout(limit)),
            Ok(Err(err)) => Err(TlsError::handshake(&err)),
            Ok(Ok(tls)) => {
                let peer = peer_info(tls.get_ref().1.peer_certificates());
                Ok((tls, peer))
            }
        };
        if let Err(err) = &result {
            log_failure("initiator", err);
        }
        result
    }

    /// The server half of the handshake on an accepted socket, bounded by
    /// `limit`. Sets `TCP_NODELAY` on the socket first, as the TCP path does.
    pub(crate) async fn accept(
        stream: TcpStream,
        config: Arc<ServerConfig>,
        limit: Duration,
    ) -> Result<(server::TlsStream<TcpStream>, PeerInfo), TlsError> {
        let _ = stream.set_nodelay(true);
        let acceptor = TlsAcceptor::from(config);
        let result = match timeout(limit, acceptor.accept(stream)).await {
            Err(_) => Err(TlsError::HandshakeTimeout(limit)),
            Ok(Err(err)) => Err(TlsError::handshake(&err)),
            Ok(Ok(tls)) => {
                let peer = peer_info(tls.get_ref().1.peer_certificates());
                Ok((tls, peer))
            }
        };
        if let Err(err) = &result {
            log_failure("acceptor", err);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_info_keeps_the_chain_in_order() {
        let peer = PeerInfo::new([Bytes::from_static(b"leaf"), Bytes::from_static(b"ca")]);
        assert_eq!(peer.certificate_chain().len(), 2);
        assert_eq!(
            peer.end_entity_certificate().map(Bytes::as_ref),
            Some(&b"leaf"[..])
        );
        assert!(!peer.is_anonymous());
        assert_eq!(format!("{peer:?}"), "PeerInfo { certificates: 2 }");
    }

    #[test]
    fn test_peer_info_default_is_anonymous() {
        let peer = PeerInfo::default();
        assert!(peer.is_anonymous());
        assert!(peer.end_entity_certificate().is_none());
    }

    #[test]
    fn test_tls_error_maps_to_its_failure() {
        let handshake = TlsError::Handshake {
            kind: std::io::ErrorKind::InvalidData,
            detail: "invalid peer certificate: UnknownIssuer".to_string(),
        };
        assert_eq!(handshake.failure(), TlsFailure::Handshake);
        assert_eq!(
            TlsError::HandshakeTimeout(Duration::from_secs(1)).failure(),
            TlsFailure::HandshakeTimeout
        );
        let rejected = TlsError::PeerRejected {
            reason: "wrong CompID".to_string(),
        };
        assert_eq!(rejected.failure(), TlsFailure::PeerRejected);
        assert_eq!(rejected.to_string(), "tls peer refused: wrong CompID");
    }
}
