/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/
//! FIX 4.4 client over TLS, using `Initiator::connect_tls` (issue #81).
//!
//! Counterpart to `fix44_tls_server`: run the server first, then this
//! client. Needs the `tls` feature:
//!
//! ```text
//! cargo run -p ironfix-example --features tls --example fix44_tls_server
//! cargo run -p ironfix-example --features tls --example fix44_tls_client
//! ```
//!
//! The client trusts exactly one authority: the certificate the server wrote
//! to `FIX_TLS_CA` (default: `ironfix-fix44-tls-ca.der` in the system
//! temporary directory) when it started. It verifies the server certificate
//! for `localhost` (`FIX_TLS_SERVER_NAME` overrides it), checks the verified
//! end-entity certificate in `authorize_peer` before its Logon is written,
//! sends one `NewOrderSingle`, waits for the `ExecutionReport` and logs out.
//!
//! The crypto provider is `ring`, selected explicitly on the configuration
//! (`ClientConfig::builder_with_provider`); IronFix enables none itself.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::info;

use ironfix_core::MsgType;
use ironfix_core::message::RawMessage;
use ironfix_core::types::CompId;
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::tls::rustls::pki_types::{CertificateDer, ServerName};
use ironfix_engine::tls::rustls::{self, ClientConfig, RootCertStore};
use ironfix_engine::{Initiator, OutboundMessage, PeerInfo};
use ironfix_session::SessionConfig;

mod common;
use common::{ExampleConfig, init_logging};

/// FIX version this example speaks, as its `BeginString` (8).
const FIX_VERSION: &str = "FIX.4.4";

/// Port dialled when `FIX_PORT` is unset.
const DEFAULT_PORT: u16 = 9879;

/// Where the server wrote its authority's certificate.
fn ca_path() -> PathBuf {
    std::env::var_os("FIX_TLS_CA")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("ironfix-fix44-tls-ca.der"))
}

/// A client configuration trusting only the authority in `ca_der`.
fn client_tls(ca_der: Vec<u8>) -> anyhow::Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der))?;
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Logs the verified server certificate and forwards each application
/// message's MsgType.
#[derive(Debug)]
struct ClientApp {
    received: mpsc::UnboundedSender<String>,
}

#[async_trait]
impl Application for ClientApp {
    async fn on_create(&self, session_id: &SessionId) {
        info!("session created: {session_id}");
    }

    async fn authorize_peer(
        &self,
        _session_id: &SessionId,
        peer: &PeerInfo,
    ) -> Result<(), RejectReason> {
        // Only the end-entity certificate is verified by TLS; the rest of the
        // chain is whatever the server chose to send.
        match peer.end_entity_certificate() {
            Some(cert) => {
                info!("server certificate verified ({} bytes DER)", cert.len());
                Ok(())
            }
            None => Err(RejectReason::new(0, "the server presented no certificate")),
        }
    }

    async fn on_logon(&self, session_id: &SessionId) {
        info!("logged on over TLS: {session_id}");
    }

    async fn on_logout(&self, session_id: &SessionId) {
        info!("logged out: {session_id}");
    }

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        let _ = self.received.send(message.msg_type().as_str().to_string());
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    let cfg = ExampleConfig::client(DEFAULT_PORT);
    let ca_path = ca_path();
    let ca_der = std::fs::read(&ca_path).map_err(|err| {
        anyhow::anyhow!(
            "cannot read the CA certificate at {} (start fix44_tls_server first): {err}",
            ca_path.display()
        )
    })?;
    let tls = client_tls(ca_der)?;
    let server_name = std::env::var("FIX_TLS_SERVER_NAME").unwrap_or_else(|_| "localhost".into());
    let server_name = ServerName::try_from(server_name)?;

    let config = SessionConfig::new(
        CompId::new(&cfg.sender_comp_id)?,
        CompId::new(&cfg.target_comp_id)?,
        FIX_VERSION,
    )
    .with_heartbeat_interval(Duration::from_secs(cfg.heartbeat_interval));
    let (received, mut inbox) = mpsc::unbounded_channel();
    let initiator = Initiator::new(config, Arc::new(ClientApp { received }))
        .with_tls_handshake_timeout(Duration::from_secs(5));

    info!("connecting to {} over TLS", cfg.addr());
    let connection = initiator.connect_tls(cfg.addr(), tls, server_name).await?;

    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, "TLS-1")
        .push_char(21, '1')
        .push_str(55, "EUR/USD")
        .push_char(54, '1')
        .push_str(60, "20261019-12:00:00.000")
        .push_str(38, "100")
        .push_char(40, '1');
    connection.send(order).await?;
    match tokio::time::timeout(Duration::from_secs(10), inbox.recv()).await {
        Ok(Some(msg_type)) => info!("received 35={msg_type} over TLS"),
        _ => info!("no reply within 10 s"),
    }

    connection.logout().await?;
    connection.wait_closed().await;
    info!("session closed: {:?}", connection.close_reason());
    Ok(())
}
