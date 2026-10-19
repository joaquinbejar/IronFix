/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/
//! FIX 4.4 server over TLS, using `Acceptor::serve_tls` (issue #81).
//!
//! Counterpart to `fix44_tls_client`: run this server first, then the client.
//! Needs the `tls` feature:
//!
//! ```text
//! cargo run -p ironfix-example --features tls --example fix44_tls_server
//! cargo run -p ironfix-example --features tls --example fix44_tls_client
//! ```
//!
//! At start-up the server generates a throwaway certificate authority and a
//! server certificate for `localhost` with rcgen. It writes the authority's
//! **certificate** (public, DER) to `FIX_TLS_CA` (default: `ironfix-fix44-tls-
//! ca.der` in the system temporary directory), so the client can trust it.
//! No private key is ever written to disk: the keys live in this process
//! only, and a new pair is generated on every run.
//!
//! The crypto provider is `ring`, selected explicitly on the configuration
//! (`ServerConfig::builder_with_provider`); IronFix enables none itself. The
//! application's `authorize_peer` logs what the TLS layer verified before the
//! Logon is read, and the session answers each `NewOrderSingle` with an
//! `ExecutionReport`, exactly as `fix44_server` does over TCP.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use tracing::{error, info};

use ironfix_core::MsgType;
use ironfix_core::message::RawMessage;
use ironfix_core::types::CompId;
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::tls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use ironfix_engine::tls::rustls::{self, ServerConfig};
use ironfix_engine::{Acceptor, Connection, OutboundMessage, PeerInfo};
use ironfix_session::SessionConfig;
use tokio::net::TcpListener;
use tokio::sync::watch;

mod common;
use common::{ExampleConfig, init_logging};

/// FIX version this example speaks, as its `BeginString` (8).
const FIX_VERSION: &str = "FIX.4.4";

/// Port bound when `FIX_PORT` is unset.
const DEFAULT_PORT: u16 = 9879;

/// Where the authority's certificate is written when `FIX_TLS_CA` is unset.
fn ca_path() -> PathBuf {
    std::env::var_os("FIX_TLS_CA")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("ironfix-fix44-tls-ca.der"))
}

/// A throwaway authority and a `localhost` server certificate it signs.
/// Returns the server configuration and the authority's certificate (DER).
fn server_tls() -> anyhow::Result<(Arc<ServerConfig>, Vec<u8>)> {
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "IronFix example CA");
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate()?)?;

    let leaf_key = KeyPair::generate()?;
    let leaf = CertificateParams::new(vec!["localhost".to_string()])?.signed_by(&leaf_key, &ca)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], key)?;
    Ok((Arc::new(config), ca.der().to_vec()))
}

/// Per-connection application: logs what TLS verified and answers each
/// `NewOrderSingle` with an `ExecutionReport` (see `fix44_server` for why the
/// handle is published on a `watch` channel).
#[derive(Debug)]
struct ServerApp {
    connection: watch::Sender<Option<Connection>>,
}

impl ServerApp {
    fn new() -> Self {
        let (connection, _rx) = watch::channel(None);
        Self { connection }
    }
}

#[async_trait]
impl Application for ServerApp {
    async fn on_create(&self, session_id: &SessionId) {
        info!("session created: {session_id}");
    }

    async fn authorize_peer(
        &self,
        session_id: &SessionId,
        peer: &PeerInfo,
    ) -> Result<(), RejectReason> {
        // No client certificate is requested here, so the peer is anonymous.
        // A server that wants mutual TLS builds its configuration with a
        // client certificate verifier and binds the end-entity certificate
        // (the only verified one) to the session's CompID here.
        info!(
            "TLS peer for {session_id}: {} certificate(s) presented",
            peer.certificate_chain().len()
        );
        Ok(())
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
        if message.msg_type() != &MsgType::NewOrderSingle {
            return Ok(());
        }
        let clid = message.get_field_str(11).unwrap_or("0");
        info!("order {clid}: acking with an ExecutionReport");
        let mut exec = OutboundMessage::new(MsgType::ExecutionReport);
        exec.push_str(37, &format!("ORD{clid}"))
            .push_str(11, clid)
            .push_str(17, &format!("EX{clid}"))
            .push_char(150, '0')
            .push_char(39, '0')
            .push_str(55, message.get_field_str(55).unwrap_or("N/A"))
            .push_str(54, message.get_field_str(54).unwrap_or("1"))
            .push_str(151, message.get_field_str(38).unwrap_or("0"))
            .push_str(14, "0")
            .push_str(6, "0");
        let mut connection_rx = self.connection.subscribe();
        tokio::spawn(async move {
            let connection = loop {
                if let Some(connection) = connection_rx.borrow_and_update().clone() {
                    break connection;
                }
                if connection_rx.changed().await.is_err() {
                    return;
                }
            };
            if let Err(err) = connection.send(exec).await {
                error!("failed to send ExecutionReport: {err}");
            }
        });
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    let cfg = ExampleConfig::server(DEFAULT_PORT);
    let (tls, ca_der) = server_tls()?;
    let ca_path = ca_path();
    std::fs::write(&ca_path, &ca_der)?;
    info!(
        "{FIX_VERSION} TLS server listening on {}; CA certificate written to {}",
        cfg.addr(),
        ca_path.display()
    );

    let listener = TcpListener::bind(&cfg.addr()).await?;
    loop {
        let (stream, peer) = listener.accept().await?;
        info!("connection from {peer}");
        let cfg = cfg.clone();
        let tls = Arc::clone(&tls);
        tokio::spawn(async move {
            if let Err(err) = serve(stream, cfg, tls).await {
                error!("session error: {err}");
            }
        });
    }
}

/// Runs the TLS handshake and one acceptor session until it closes.
async fn serve(
    stream: tokio::net::TcpStream,
    cfg: ExampleConfig,
    tls: Arc<ServerConfig>,
) -> anyhow::Result<()> {
    let config = SessionConfig::new(
        CompId::new(&cfg.sender_comp_id)?,
        CompId::new(&cfg.target_comp_id)?,
        FIX_VERSION,
    )
    .with_heartbeat_interval(Duration::from_secs(cfg.heartbeat_interval));
    let app = Arc::new(ServerApp::new());
    let acceptor =
        Acceptor::new(config, Arc::clone(&app)).with_tls_handshake_timeout(Duration::from_secs(5));
    let connection = acceptor.serve_tls(stream, tls).await?;
    let _ = app.connection.send_replace(Some(connection.clone()));
    connection.wait_closed().await;
    info!("session closed: {:?}", connection.close_reason());
    Ok(())
}
