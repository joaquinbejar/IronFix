//! FIX 4.4 Client Example using the `ironfix-engine` Initiator.
//!
//! Counterpart to `fix44_server`: run the server first, then this client.
//! Unlike `fix44_client` (hand-rolled framing and session logic), this
//! example lets the engine own the socket: TCP dial, `FixCodec` framing,
//! Logon handshake, heartbeats/TestRequests, and sequence numbers.

use std::sync::Arc;
use std::time::Duration;
use tracing::info;

use async_trait::async_trait;
use ironfix_core::MsgType;
use ironfix_core::message::RawMessage;
use ironfix_core::types::CompId;
use ironfix_engine::application::{Application, NoOpApplication, RejectReason, SessionId};
use ironfix_engine::{Initiator, OutboundMessage};
use ironfix_session::SessionConfigBuilder;

mod common;
use common::{ExampleConfig, init_logging};

const FIX_VERSION: &str = "FIX.4.4";

/// Logs execution reports; everything else is engine-managed.
#[derive(Debug, Default)]
struct LoggingApp(NoOpApplication);

#[async_trait]
impl Application for LoggingApp {
    async fn on_create(&self, session_id: &SessionId) {
        info!("session created: {session_id}");
    }

    async fn on_logon(&self, session_id: &SessionId) {
        info!("logged on: {session_id}");
    }

    async fn on_logout(&self, session_id: &SessionId) {
        info!("logged out: {session_id}");
    }

    /// Stamps credentials onto the outbound Logon.
    ///
    /// The body is mutable and the engine encodes exactly what this hands
    /// back, so the fields added here reach the counterparty. Every other
    /// administrative message goes out untouched.
    async fn to_admin(&self, message: &mut OutboundMessage, _session_id: &SessionId) {
        if message.msg_type() == &MsgType::Logon {
            message.push_str(553, "DEMO-USER");
        }
    }

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
        info!(
            "app message received: 35={} 37={:?} 39={:?}",
            message.msg_type(),
            message.get_field_str(37),
            message.get_field_str(39),
        );
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();
    let cfg = ExampleConfig::client();
    info!("{FIX_VERSION} engine client connecting to {}", cfg.addr());

    // The builder validates every knob, so a bad CompID or an out-of-range
    // heartbeat is reported here rather than on the wire.
    let config = SessionConfigBuilder::new()
        .sender_comp_id(CompId::new(&cfg.sender_comp_id)?)
        .target_comp_id(CompId::new(&cfg.target_comp_id)?)
        .begin_string(FIX_VERSION)
        .heartbeat_interval(Duration::from_secs(cfg.heartbeat_interval))
        .build()?;

    let initiator = Initiator::new(config, Arc::new(LoggingApp::default()))
        .with_connect_timeout(Duration::from_secs(5));
    let connection = initiator.connect(cfg.addr()).await?;

    // Send a NewOrderSingle; the engine stamps the header and MsgSeqNum.
    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, "ORD001")
        .push_str(55, "AAPL")
        .push_char(54, '1')
        .push_str(60, "20260714-00:00:00.000")
        .push_uint(38, 100)
        .push_str(44, "150.50")
        .push_char(40, '2');
    connection.send(order).await?;

    // Let the session breathe (heartbeats are automatic), then log out.
    tokio::time::sleep(Duration::from_secs(2)).await;
    connection.logout().await?;
    connection.wait_closed().await;
    info!("Done");
    Ok(())
}
