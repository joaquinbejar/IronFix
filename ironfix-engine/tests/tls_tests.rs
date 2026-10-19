/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! Integration tests for issue #81 (ADR-0009): FIX over TLS in both roles.
//!
//! Built only with the `tls` feature. Every certificate is generated at test
//! time with rcgen, and every rustls configuration is built on the `ring`
//! crypto provider, a dev-dependency: the engine itself enables no provider.
//! No private key is committed.
//!
//! Covered: an initiator and an acceptor, and an initiator and an
//! `AcceptorRegistry`, completing Logon, exchanging an application message
//! each way and logging out over mutual TLS, with each side's
//! `authorize_peer` seeing the other's certificate; an untrusted and an
//! expired server certificate failing the initiator with a typed error before
//! any Logon; a client certificate from the wrong CA failing the acceptor's
//! handshake before `on_create`; a peer that does not speak TLS; a handshake
//! that never completes, in both roles, ending at the TLS handshake timeout;
//! `authorize_peer` refusing in both roles, with nothing written to the
//! refused peer; and the `Password` (554), `NewPassword` (925) and `RawData`
//! (96) of a Logon never reaching a log line, on the accepted path and on a
//! refused one.

#![cfg(feature = "tls")]

use async_trait::async_trait;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::CompId;
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::tls::rustls;
use ironfix_engine::{
    Acceptor, AcceptorRegistry, CloseReason, Connection, EngineError, Initiator, OutboundMessage,
    PeerInfo, TlsError, TlsFailure,
};
use ironfix_session::SessionConfig;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, date_time_ymd};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// How long a test waits for any one step before failing.
const STEP: Duration = Duration::from_secs(10);

/// The secrets a Logon carries in the credential-logging test.
const PASSWORD: &str = "pw-554-Sekr1t";
const NEW_PASSWORD: &str = "pw-925-N3wSekr1t";
const RAW_DATA: &str = "raw-96-Sekr1tBlob";

/// Fails the test with context instead of `.unwrap()` / `.expect()`.
#[track_caller]
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what}: {err:?}"),
    }
}

/// Fails the test with context instead of `.unwrap()` / `.expect()`.
#[track_caller]
fn some<T>(value: Option<T>, what: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{what}"),
    }
}

#[track_caller]
fn comp_id(value: &str) -> CompId {
    ok(CompId::new(value), "test CompId must be valid")
}

/// The venue's session for `member`.
fn venue_config(member: &str) -> SessionConfig {
    SessionConfig::new(comp_id("VENUE"), comp_id(member), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// The member's own session.
fn member_config(member: &str) -> SessionConfig {
    SessionConfig::new(comp_id(member), comp_id("VENUE"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
        .with_logon_timeout(Duration::from_secs(5))
}

// ---------------------------------------------------------------------------
// Certificates and rustls configurations
// ---------------------------------------------------------------------------

/// A certificate authority generated for one test.
struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl Ca {
    fn new(name: &str) -> Self {
        let mut params = ok(CertificateParams::new(Vec::<String>::new()), "CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let key = ok(KeyPair::generate(), "CA key");
        Self {
            issuer: ok(CertifiedIssuer::self_signed(params, key), "CA certificate"),
        }
    }

    fn der(&self) -> CertificateDer<'static> {
        self.issuer.der().clone()
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        ok(roots.add(self.der()), "add CA root");
        roots
    }

    /// A leaf for `name` (a DNS name, also its common name), valid now.
    fn leaf(&self, name: &str) -> Leaf {
        self.leaf_with(name, false)
    }

    /// A leaf whose validity ended long ago.
    fn expired_leaf(&self, name: &str) -> Leaf {
        self.leaf_with(name, true)
    }

    fn leaf_with(&self, name: &str, expired: bool) -> Leaf {
        let mut params = ok(
            CertificateParams::new(vec![name.to_string()]),
            "leaf params",
        );
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        if expired {
            params.not_before = date_time_ymd(2000, 1, 1);
            params.not_after = date_time_ymd(2001, 1, 1);
        }
        let key = ok(KeyPair::generate(), "leaf key");
        let cert = ok(params.signed_by(&key, &self.issuer), "leaf certificate");
        Leaf {
            cert: cert.der().clone(),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        }
    }
}

/// A leaf certificate and its private key.
struct Leaf {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl Leaf {
    fn key(&self) -> PrivateKeyDer<'static> {
        self.key.clone_key()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A server configuration presenting `server`, requiring a client
/// certificate issued by `client_ca` when one is given.
fn server_config(server: &Leaf, client_ca: Option<&Ca>) -> Arc<ServerConfig> {
    let builder = ok(
        ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions(),
        "server protocol versions",
    );
    let builder = match client_ca {
        Some(ca) => {
            let verifier = ok(
                rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(ca.roots()),
                    provider(),
                )
                .build(),
                "client verifier",
            );
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    Arc::new(ok(
        builder.with_single_cert(vec![server.cert.clone()], server.key()),
        "server certificate",
    ))
}

/// A client configuration trusting `server_ca`, presenting `client` when one
/// is given.
fn client_config(server_ca: &Ca, client: Option<&Leaf>) -> Arc<ClientConfig> {
    let builder = ok(
        ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions(),
        "client protocol versions",
    )
    .with_root_certificates(server_ca.roots());
    Arc::new(match client {
        Some(leaf) => ok(
            builder.with_client_auth_cert(vec![leaf.cert.clone()], leaf.key()),
            "client certificate",
        ),
        None => builder.with_no_client_auth(),
    })
}

fn venue_name() -> ServerName<'static> {
    ok(ServerName::try_from("venue.test"), "server name")
}

/// A loopback listener and its address.
async fn listener() -> (TcpListener, std::net::SocketAddr) {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind loopback");
    let addr = ok(listener.local_addr(), "listener address");
    (listener, addr)
}

// ---------------------------------------------------------------------------
// The recording application
// ---------------------------------------------------------------------------

/// Records the callbacks in order, the peers it was asked to authorize, the
/// close reasons, and every application message.
#[derive(Debug)]
struct RecordingApp {
    events: Mutex<Vec<String>>,
    peers: Mutex<Vec<PeerInfo>>,
    closes: Mutex<Vec<CloseReason>>,
    app_tx: mpsc::UnboundedSender<String>,
    /// Refuse every peer in `authorize_peer`.
    refuse_peers: AtomicBool,
    /// Refuse every Logon in `from_admin`.
    refuse_logons: AtomicBool,
    /// Stamp credentials (553, 554, 925, 95/96) on the outbound Logon.
    stamp_credentials: AtomicBool,
}

impl RecordingApp {
    fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<String>) {
        let (app_tx, app_rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                events: Mutex::new(Vec::new()),
                peers: Mutex::new(Vec::new()),
                closes: Mutex::new(Vec::new()),
                app_tx,
                refuse_peers: AtomicBool::new(false),
                refuse_logons: AtomicBool::new(false),
                stamp_credentials: AtomicBool::new(false),
            }),
            app_rx,
        )
    }

    fn record(&self, event: &str) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event.to_string());
        }
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }

    fn peers(&self) -> Vec<PeerInfo> {
        self.peers.lock().map(|p| p.clone()).unwrap_or_default()
    }

    fn closes(&self) -> Vec<CloseReason> {
        self.closes.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl Application for RecordingApp {
    async fn on_create(&self, _session_id: &SessionId) {
        self.record("on_create");
    }

    async fn authorize_peer(
        &self,
        _session_id: &SessionId,
        peer: &PeerInfo,
    ) -> Result<(), RejectReason> {
        self.record("authorize_peer");
        if let Ok(mut peers) = self.peers.lock() {
            peers.push(peer.clone());
        }
        if self.refuse_peers.load(Ordering::SeqCst) {
            return Err(RejectReason::new(0, "certificate not bound to this CompID"));
        }
        Ok(())
    }

    async fn on_logon(&self, _session_id: &SessionId) {
        self.record("on_logon");
    }

    async fn on_logout(&self, _session_id: &SessionId) {
        self.record("on_logout");
    }

    async fn on_session_closed(&self, session_id: &SessionId, reason: &CloseReason) {
        if let Ok(mut closes) = self.closes.lock() {
            closes.push(reason.clone());
        }
        if reason.was_active() {
            self.on_logout(session_id).await;
        }
    }

    async fn to_admin(&self, message: &mut OutboundMessage, _session_id: &SessionId) {
        if message.msg_type() == &MsgType::Logon && self.stamp_credentials.load(Ordering::SeqCst) {
            message
                .push_str(553, "member")
                .push_str(554, PASSWORD)
                .push_str(925, NEW_PASSWORD)
                .push_data(95, 96, RAW_DATA.as_bytes());
        }
    }

    async fn from_admin(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        if message.msg_type() == &MsgType::Logon && self.refuse_logons.load(Ordering::SeqCst) {
            return Err(RejectReason::new(0, "credentials refused"));
        }
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        let _ = self.app_tx.send(message.msg_type().as_str().to_string());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shared session flow
// ---------------------------------------------------------------------------

/// Sends a message each way, then logs out from the initiator and waits for
/// both sides to close.
async fn exchange_and_logout(
    member: &Connection,
    venue: &Connection,
    member_rx: &mut mpsc::UnboundedReceiver<String>,
    venue_rx: &mut mpsc::UnboundedReceiver<String>,
) {
    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order.push_str(11, "ORDER-1");
    ok(member.send(order).await, "send order");
    let got = some(
        ok(timeout(STEP, venue_rx.recv()).await, "venue receives"),
        "venue channel open",
    );
    assert_eq!(got, "D");

    let mut exec = OutboundMessage::new(MsgType::ExecutionReport);
    exec.push_str(37, "EXEC-1");
    ok(venue.send(exec).await, "send execution report");
    let got = some(
        ok(timeout(STEP, member_rx.recv()).await, "member receives"),
        "member channel open",
    );
    assert_eq!(got, "8");

    ok(member.logout().await, "logout");
    ok(timeout(STEP, member.wait_closed()).await, "member closes");
    ok(timeout(STEP, venue.wait_closed()).await, "venue closes");
    assert!(
        member.close_reason().is_some_and(|r| r.is_graceful()),
        "{:?}",
        member.close_reason()
    );
}

/// The TLS failures of the close reasons `app` was given; any other reason
/// fails the test.
fn tls_closes(app: &RecordingApp) -> Vec<TlsFailure> {
    app.closes()
        .into_iter()
        .map(|reason| match reason {
            CloseReason::Tls { failure, .. } => failure,
            other => panic!("expected a TLS close reason, got {other:?}"),
        })
        .collect()
}

/// The `EngineError::Tls` failure an error carries, if any.
fn tls_failure(err: &EngineError) -> Option<TlsFailure> {
    match err {
        EngineError::Tls(tls) => Some(tls.failure()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Both roles over TLS
// ---------------------------------------------------------------------------

/// Initiator and acceptor complete Logon, exchange a message each way and
/// log out over mutual TLS; each side's `authorize_peer` sees the other's
/// certificate before `on_logon`.
#[tokio::test]
async fn test_initiator_and_acceptor_over_mutual_tls() {
    log_capture();
    let server_ca = Ca::new("server CA");
    let client_ca = Ca::new("client CA");
    let server_leaf = server_ca.leaf("venue.test");
    let client_leaf = client_ca.leaf("MEMBER");

    let (listener, addr) = listener().await;
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_config("MEMBER"), Arc::clone(&venue_app));
    let server = server_config(&server_leaf, Some(&client_ca));
    let served = tokio::spawn(async move {
        let (stream, _) = ok(listener.accept().await, "accept");
        acceptor.serve_tls(stream, server).await
    });

    let (member_app, mut member_rx) = RecordingApp::new();
    let initiator = Initiator::new(member_config("MEMBER"), Arc::clone(&member_app));
    let member = ok(
        initiator
            .connect_tls(
                addr,
                client_config(&server_ca, Some(&client_leaf)),
                venue_name(),
            )
            .await,
        "connect_tls",
    );
    let venue = ok(
        ok(timeout(STEP, served).await, "serve in time"),
        "serve task",
    );
    let venue = ok(venue, "serve_tls");

    // Each side saw the other's end-entity certificate, before on_logon.
    let member_peers = member_app.peers();
    assert_eq!(member_peers.len(), 1);
    assert_eq!(
        member_peers[0].end_entity_certificate().map(|c| c.as_ref()),
        Some(server_leaf.cert.as_ref())
    );
    let venue_peers = venue_app.peers();
    assert_eq!(venue_peers.len(), 1);
    assert_eq!(
        venue_peers[0].end_entity_certificate().map(|c| c.as_ref()),
        Some(client_leaf.cert.as_ref())
    );

    exchange_and_logout(&member, &venue, &mut member_rx, &mut venue_rx).await;
    for app in [&member_app, &venue_app] {
        assert_eq!(
            app.events(),
            ["on_create", "authorize_peer", "on_logon", "on_logout"]
        );
    }
}

/// A registry routes a Logon read inside TLS, and the routed session's
/// `authorize_peer` sees the client certificate.
#[tokio::test]
async fn test_registry_over_tls() {
    log_capture();
    let server_ca = Ca::new("server CA");
    let client_ca = Ca::new("client CA");
    let server_leaf = server_ca.leaf("venue.test");
    let client_leaf = client_ca.leaf("ALPHA");

    let (venue_app, mut venue_rx) = RecordingApp::new();
    let registry = Arc::new(AcceptorRegistry::new());
    ok(
        registry.register(Acceptor::new(venue_config("ALPHA"), Arc::clone(&venue_app))),
        "register ALPHA",
    );
    ok(
        registry.register(Acceptor::new(venue_config("BETA"), Arc::clone(&venue_app))),
        "register BETA",
    );

    let (listener, addr) = listener().await;
    let server = server_config(&server_leaf, Some(&client_ca));
    let served_registry = Arc::clone(&registry);
    let served = tokio::spawn(async move {
        let (stream, _) = ok(listener.accept().await, "accept");
        served_registry.serve_tls(stream, server).await
    });

    let (member_app, mut member_rx) = RecordingApp::new();
    let initiator = Initiator::new(member_config("ALPHA"), Arc::clone(&member_app));
    let member = ok(
        initiator
            .connect_tls(
                addr,
                client_config(&server_ca, Some(&client_leaf)),
                venue_name(),
            )
            .await,
        "connect_tls",
    );
    let venue = ok(
        ok(ok(timeout(STEP, served).await, "serve in time"), "task"),
        "registry serve_tls",
    );
    assert_eq!(venue.session_id().to_string(), "FIX.4.4:VENUE->ALPHA");
    assert_eq!(
        venue_app.peers()[0]
            .end_entity_certificate()
            .map(|c| c.as_ref()),
        Some(client_leaf.cert.as_ref())
    );
    exchange_and_logout(&member, &venue, &mut member_rx, &mut venue_rx).await;
}

// ---------------------------------------------------------------------------
// Handshake failures
// ---------------------------------------------------------------------------

/// Runs an initiator against an acceptor presenting `server_leaf`, trusting
/// `trusted`, and returns the initiator's error, its app, and the acceptor's
/// result.
async fn initiator_against(
    server_leaf: &Leaf,
    trusted: &Ca,
) -> (
    EngineError,
    Arc<RecordingApp>,
    Result<Connection, EngineError>,
) {
    let (listener, addr) = listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_config("MEMBER"), venue_app);
    let server = server_config(server_leaf, None);
    let served = tokio::spawn(async move {
        let (stream, _) = ok(listener.accept().await, "accept");
        acceptor.serve_tls(stream, server).await
    });

    let (member_app, _member_rx) = RecordingApp::new();
    let initiator = Initiator::new(member_config("MEMBER"), Arc::clone(&member_app));
    let err = match initiator
        .connect_tls(addr, client_config(trusted, None), venue_name())
        .await
    {
        Ok(_) => panic!("the initiator must refuse the server certificate"),
        Err(err) => err,
    };
    let venue = ok(ok(timeout(STEP, served).await, "serve in time"), "task");
    (err, member_app, venue)
}

/// A server certificate from a CA the initiator does not trust fails the
/// initiator with a typed TLS error, before any Logon and before
/// `authorize_peer`.
#[tokio::test]
async fn test_untrusted_server_certificate_fails_the_initiator() {
    log_capture();
    let rogue_ca = Ca::new("rogue CA");
    let trusted_ca = Ca::new("trusted CA");
    let (err, member_app, venue) =
        initiator_against(&rogue_ca.leaf("venue.test"), &trusted_ca).await;

    assert_eq!(tls_failure(&err), Some(TlsFailure::Handshake), "{err:?}");
    assert!(
        err.to_string().contains("UnknownIssuer"),
        "the error names the failure: {err}"
    );
    assert_eq!(member_app.events(), ["on_create"]);
    assert_eq!(tls_closes(&member_app), [TlsFailure::Handshake]);
    let venue_err = match venue {
        Ok(_) => panic!("the acceptor must not get a session"),
        Err(err) => err,
    };
    assert_eq!(tls_failure(&venue_err), Some(TlsFailure::Handshake));
}

/// An expired server certificate fails the initiator with a typed TLS error.
#[tokio::test]
async fn test_expired_server_certificate_fails_the_initiator() {
    log_capture();
    let ca = Ca::new("server CA");
    let (err, member_app, _venue) = initiator_against(&ca.expired_leaf("venue.test"), &ca).await;
    assert_eq!(tls_failure(&err), Some(TlsFailure::Handshake), "{err:?}");
    assert!(err.to_string().contains("expired"), "{err}");
    assert!(!member_app.events().contains(&"on_logon".to_string()));
}

/// Mutual TLS: a client certificate from the wrong CA fails the acceptor's
/// handshake before `on_create`, so no session exists on the venue and the
/// member never logs on.
#[tokio::test]
async fn test_mutual_tls_with_a_wrong_client_certificate_fails_before_logon() {
    log_capture();
    let server_ca = Ca::new("server CA");
    let client_ca = Ca::new("client CA");
    let other_ca = Ca::new("other CA");
    let server_leaf = server_ca.leaf("venue.test");
    let wrong_client = other_ca.leaf("MEMBER");

    let (listener, addr) = listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_config("MEMBER"), Arc::clone(&venue_app));
    let server = server_config(&server_leaf, Some(&client_ca));
    let served = tokio::spawn(async move {
        let (stream, _) = ok(listener.accept().await, "accept");
        acceptor.serve_tls(stream, server).await
    });

    let (member_app, _member_rx) = RecordingApp::new();
    let initiator = Initiator::new(member_config("MEMBER"), Arc::clone(&member_app));
    let member = initiator
        .connect_tls(
            addr,
            client_config(&server_ca, Some(&wrong_client)),
            venue_name(),
        )
        .await;
    assert!(member.is_err(), "the member must not reach Active");
    assert!(!member_app.events().contains(&"on_logon".to_string()));

    let venue_err = match ok(timeout(STEP, served).await, "serve in time") {
        Ok(Ok(_)) => panic!("the acceptor must refuse the client certificate"),
        Ok(Err(err)) => err,
        Err(err) => panic!("serve task: {err:?}"),
    };
    assert_eq!(tls_failure(&venue_err), Some(TlsFailure::Handshake));
    assert!(venue_app.events().is_empty(), "{:?}", venue_app.events());
    assert!(venue_app.closes().is_empty());
}

/// A client that does not speak TLS fails the acceptor's handshake.
#[tokio::test]
async fn test_plaintext_client_fails_the_tls_handshake() {
    log_capture();
    let ca = Ca::new("server CA");
    let (listener, addr) = listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_config("MEMBER"), Arc::clone(&venue_app));
    let server = server_config(&ca.leaf("venue.test"), None);
    let served = tokio::spawn(async move {
        let (stream, _) = ok(listener.accept().await, "accept");
        acceptor.serve_tls(stream, server).await
    });

    let mut plain = ok(TcpStream::connect(addr).await, "dial");
    ok(
        plain
            .write_all(b"8=FIX.4.4\x019=5\x0135=A\x0110=000\x01")
            .await,
        "write plaintext",
    );
    let venue_err = match ok(timeout(STEP, served).await, "serve in time") {
        Ok(Ok(_)) => panic!("plaintext must not reach a session"),
        Ok(Err(err)) => err,
        Err(err) => panic!("serve task: {err:?}"),
    };
    assert_eq!(tls_failure(&venue_err), Some(TlsFailure::Handshake));
    assert!(venue_app.events().is_empty());
}

/// A client that connects and never starts the handshake holds `serve_tls`
/// only for the TLS handshake timeout.
#[tokio::test]
async fn test_acceptor_tls_handshake_timeout() {
    log_capture();
    let ca = Ca::new("server CA");
    let (listener, addr) = listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let limit = Duration::from_millis(200);
    let acceptor = Acceptor::new(venue_config("MEMBER"), Arc::clone(&venue_app))
        .with_tls_handshake_timeout(limit);
    assert_eq!(acceptor.tls_handshake_timeout(), limit);
    let server = server_config(&ca.leaf("venue.test"), None);
    let served = tokio::spawn(async move {
        let (stream, _) = ok(listener.accept().await, "accept");
        acceptor.serve_tls(stream, server).await
    });

    let _silent = ok(TcpStream::connect(addr).await, "dial");
    let venue_err = match ok(timeout(STEP, served).await, "serve in time") {
        Ok(Ok(_)) => panic!("a silent client must not reach a session"),
        Ok(Err(err)) => err,
        Err(err) => panic!("serve task: {err:?}"),
    };
    assert!(
        matches!(venue_err, EngineError::Tls(TlsError::HandshakeTimeout(d)) if d == limit),
        "{venue_err:?}"
    );
    assert!(venue_app.events().is_empty());
}

/// A server that accepts the TCP connection and never answers the
/// ClientHello fails the initiator at the TLS handshake timeout, reported as
/// `CloseReason::Tls`.
#[tokio::test]
async fn test_initiator_tls_handshake_timeout() {
    log_capture();
    let ca = Ca::new("server CA");
    let (listener, addr) = listener().await;
    let mute = tokio::spawn(async move {
        let (mut stream, _) = ok(listener.accept().await, "accept");
        let mut buf = [0_u8; 1024];
        // Read and discard until the client gives up.
        while let Ok(n) = stream.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    });

    let (member_app, _member_rx) = RecordingApp::new();
    let limit = Duration::from_millis(200);
    let initiator = Initiator::new(member_config("MEMBER"), Arc::clone(&member_app))
        .with_tls_handshake_timeout(limit);
    assert_eq!(initiator.tls_handshake_timeout(), limit);
    let err = match timeout(
        STEP,
        initiator.connect_tls(addr, client_config(&ca, None), venue_name()),
    )
    .await
    {
        Ok(Ok(_)) => panic!("a mute server must not yield a session"),
        Ok(Err(err)) => err,
        Err(_) => panic!("the TLS handshake timeout must bound connect_tls"),
    };
    assert!(
        matches!(err, EngineError::Tls(TlsError::HandshakeTimeout(d)) if d == limit),
        "{err:?}"
    );
    assert_eq!(tls_closes(&member_app), [TlsFailure::HandshakeTimeout]);
    let _ = timeout(STEP, mute).await;
}

// ---------------------------------------------------------------------------
// authorize_peer refusals
// ---------------------------------------------------------------------------

/// The acceptor's `authorize_peer` refuses the client: the call fails with
/// `TlsError::PeerRejected`, nothing is written back, `on_logon` never runs,
/// and the close is reported as `CloseReason::Tls`.
#[tokio::test]
async fn test_acceptor_authorize_peer_refusal() {
    log_capture();
    let server_ca = Ca::new("server CA");
    let client_ca = Ca::new("client CA");
    let server_leaf = server_ca.leaf("venue.test");
    let client_leaf = client_ca.leaf("MEMBER");

    let (listener, addr) = listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    venue_app.refuse_peers.store(true, Ordering::SeqCst);
    let acceptor = Acceptor::new(venue_config("MEMBER"), Arc::clone(&venue_app));
    let server = server_config(&server_leaf, Some(&client_ca));
    let served = tokio::spawn(async move {
        let (stream, _) = ok(listener.accept().await, "accept");
        acceptor.serve_tls(stream, server).await
    });

    let (member_app, _member_rx) = RecordingApp::new();
    let initiator = Initiator::new(member_config("MEMBER"), Arc::clone(&member_app));
    let member = initiator
        .connect_tls(
            addr,
            client_config(&server_ca, Some(&client_leaf)),
            venue_name(),
        )
        .await;
    match member {
        Ok(_) => panic!("a refused member must not reach Active"),
        // No Logon reply: the stream just closes.
        Err(err) => assert!(
            matches!(err, EngineError::Closed | EngineError::Codec(_)),
            "{err:?}"
        ),
    }

    let venue_err = match ok(timeout(STEP, served).await, "serve in time") {
        Ok(Ok(_)) => panic!("the acceptor must refuse the peer"),
        Ok(Err(err)) => err,
        Err(err) => panic!("serve task: {err:?}"),
    };
    assert!(
        matches!(&venue_err, EngineError::Tls(TlsError::PeerRejected { reason, .. })
            if reason == "certificate not bound to this CompID"),
        "{venue_err:?}"
    );
    assert_eq!(venue_app.events(), ["on_create", "authorize_peer"]);
    assert_eq!(tls_closes(&venue_app), [TlsFailure::PeerRejected]);
}

/// The initiator's `authorize_peer` refuses the server: the Logon, and the
/// credentials on it, are never written.
#[tokio::test]
async fn test_initiator_authorize_peer_refusal_writes_no_logon() {
    log_capture();
    let ca = Ca::new("server CA");
    let server = server_config(&ca.leaf("venue.test"), None);
    let (listener, addr) = listener().await;
    // A bare TLS server that records every byte it receives.
    let received = tokio::spawn(async move {
        let (stream, _) = ok(listener.accept().await, "accept");
        let mut tls = ok(
            tokio_rustls::TlsAcceptor::from(server).accept(stream).await,
            "server handshake",
        );
        let mut bytes = Vec::new();
        let _ = timeout(STEP, tls.read_to_end(&mut bytes)).await;
        bytes
    });

    let (member_app, _member_rx) = RecordingApp::new();
    member_app.refuse_peers.store(true, Ordering::SeqCst);
    member_app.stamp_credentials.store(true, Ordering::SeqCst);
    let initiator = Initiator::new(member_config("MEMBER"), Arc::clone(&member_app));
    let err = match initiator
        .connect_tls(addr, client_config(&ca, None), venue_name())
        .await
    {
        Ok(_) => panic!("a refused server must not yield a session"),
        Err(err) => err,
    };
    assert_eq!(tls_failure(&err), Some(TlsFailure::PeerRejected), "{err:?}");
    assert_eq!(member_app.events(), ["on_create", "authorize_peer"]);
    assert_eq!(tls_closes(&member_app), [TlsFailure::PeerRejected]);
    let bytes = ok(timeout(STEP, received).await, "server ends");
    let bytes = ok(bytes, "server task");
    assert!(bytes.is_empty(), "nothing is written: {bytes:?}");
}

/// `establish_with_peer` and `serve_stream_with_peer` carry a peer from a
/// caller's own TLS stack (here, none: a pipe) to `authorize_peer`.
#[tokio::test]
async fn test_with_peer_entry_points_reach_authorize_peer() {
    log_capture();
    let (member_io, venue_io) = tokio::io::duplex(64 * 1024);
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_config("MEMBER"), Arc::clone(&venue_app));
    let served = tokio::spawn(async move {
        acceptor
            .serve_stream_with_peer(
                venue_io,
                PeerInfo::new([bytes::Bytes::from_static(b"client")]),
            )
            .await
    });
    let (member_app, mut member_rx) = RecordingApp::new();
    let initiator = Initiator::new(member_config("MEMBER"), Arc::clone(&member_app));
    let member = ok(
        initiator
            .establish_with_peer(
                member_io,
                PeerInfo::new([bytes::Bytes::from_static(b"venue")]),
            )
            .await,
        "establish_with_peer",
    );
    let venue = ok(
        ok(ok(timeout(STEP, served).await, "in time"), "task"),
        "serve",
    );
    assert_eq!(
        member_app.peers()[0].certificate_chain(),
        [bytes::Bytes::from_static(b"venue")]
    );
    assert_eq!(
        venue_app.peers()[0].certificate_chain(),
        [bytes::Bytes::from_static(b"client")]
    );
    exchange_and_logout(&member, &venue, &mut member_rx, &mut venue_rx).await;
}

// ---------------------------------------------------------------------------
// Credentials are never logged
// ---------------------------------------------------------------------------

/// A tracing subscriber that renders every event and span field, at every
/// level, into one string.
#[derive(Debug, Default)]
struct LogCapture {
    text: Arc<Mutex<String>>,
    next_span: AtomicU64,
}

/// Writes `name=value` for each field it visits.
struct Render<'a>(&'a mut String);

impl tracing::field::Visit for Render<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, "{}={:?} ", field.name(), value);
    }
}

impl LogCapture {
    fn render(&self, record: impl FnOnce(&mut Render<'_>)) {
        if let Ok(mut text) = self.text.lock() {
            record(&mut Render(&mut text));
            text.push('\n');
        }
    }
}

impl tracing::Subscriber for LogCapture {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        self.render(|render| span.record(render));
        let id = self.next_span.fetch_add(1, Ordering::Relaxed);
        match id.checked_add(1) {
            Some(id) => tracing::span::Id::from_u64(id),
            None => {
                debug_assert!(false, "span ids exhausted");
                tracing::span::Id::from_u64(1)
            }
        }
    }

    fn record(&self, _span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        self.render(|render| values.record(render));
    }

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        self.render(|render| {
            let _ = write!(render.0, "{} ", event.metadata().level());
            event.record(render);
        });
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// The log every test of this binary writes to: one global subscriber,
/// installed by whichever test runs first. A scoped (`set_default`)
/// subscriber would race the other tests' threads over the callsite interest
/// cache and miss events.
fn log_capture() -> Arc<Mutex<String>> {
    static CAPTURE: OnceLock<Arc<Mutex<String>>> = OnceLock::new();
    Arc::clone(CAPTURE.get_or_init(|| {
        let capture = LogCapture::default();
        let text = Arc::clone(&capture.text);
        if tracing::subscriber::set_global_default(capture).is_err() {
            panic!("no other global subscriber is installed in this binary");
        }
        text
    }))
}

/// Asserts that none of the Logon's secrets reached the captured log.
#[track_caller]
fn assert_no_secret(log: &str) {
    for secret in [PASSWORD, NEW_PASSWORD, RAW_DATA] {
        assert!(!log.contains(secret), "{secret} was logged:\n{log}");
    }
}

/// A Logon carrying `Password` (554), `NewPassword` (925) and `RawData` (96)
/// over TLS: accepted, refused by `from_admin`, and stopped by an untrusted
/// server certificate, with every log line at every level captured (those of
/// every other test in this binary that has run so far as well). No secret
/// appears in the log.
#[tokio::test]
async fn test_credentials_are_never_logged_over_tls() {
    let text = log_capture();

    let server_ca = Ca::new("server CA");
    let server_leaf = server_ca.leaf("venue.test");

    for refuse in [false, true] {
        let (listener, addr) = listener().await;
        let (venue_app, mut venue_rx) = RecordingApp::new();
        venue_app.refuse_logons.store(refuse, Ordering::SeqCst);
        let acceptor = Acceptor::new(venue_config("MEMBER"), Arc::clone(&venue_app));
        let server = server_config(&server_leaf, None);
        let served = tokio::spawn(async move {
            let (stream, _) = ok(listener.accept().await, "accept");
            acceptor.serve_tls(stream, server).await
        });

        let (member_app, mut member_rx) = RecordingApp::new();
        member_app.stamp_credentials.store(true, Ordering::SeqCst);
        let initiator = Initiator::new(member_config("MEMBER"), Arc::clone(&member_app));
        let member = initiator
            .connect_tls(addr, client_config(&server_ca, None), venue_name())
            .await;
        let venue = ok(ok(timeout(STEP, served).await, "serve in time"), "task");
        if refuse {
            assert!(member.is_err());
            assert!(matches!(venue, Err(EngineError::LogonRejected { .. })));
        } else {
            let member = ok(member, "connect_tls");
            let venue = ok(venue, "serve_tls");
            exchange_and_logout(&member, &venue, &mut member_rx, &mut venue_rx).await;
        }
    }

    // A server certificate the initiator does not trust, after the Logon
    // stamps its credentials in `to_admin`: the handshake failure is logged.
    let rogue_ca = Ca::new("rogue CA");
    let (listener, addr) = listener().await;
    let server = server_config(&rogue_ca.leaf("venue.test"), None);
    let acceptor = Acceptor::new(venue_config("MEMBER"), RecordingApp::new().0);
    let served = tokio::spawn(async move {
        let (stream, _) = ok(listener.accept().await, "accept");
        acceptor.serve_tls(stream, server).await
    });
    let (member_app, _member_rx) = RecordingApp::new();
    member_app.stamp_credentials.store(true, Ordering::SeqCst);
    let initiator = Initiator::new(member_config("MEMBER"), member_app);
    assert!(
        initiator
            .connect_tls(addr, client_config(&server_ca, None), venue_name())
            .await
            .is_err()
    );
    let _ = timeout(STEP, served).await;

    tracing::info!("capture probe");
    let log = text.lock().map(|t| t.clone()).unwrap_or_default();
    assert!(log.contains("capture probe"), "the capture works:\n{log}");
    assert!(
        log.contains("TLS handshake failed"),
        "the capture saw the engine's log lines:\n{log}"
    );
    assert_no_secret(&log);
}
