/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 13/11/26
******************************************************************************/

//! Integration tests for the peer logout hold (issue #214): an application
//! that holds its reply to the counterparty's Logout until it has sent what
//! it owes.
//!
//! A stub initiator sends a NewOrderSingle and a Logout in one write to an
//! `Acceptor`. Without the hold the Logout is answered at once, as before.
//! With it, `on_peer_logout` runs after `from_app` has seen the order; an
//! execution report the application sends before `Connection::reply_logout`
//! is on the wire before the reply; an application message after the Logout
//! is not delivered; and the logout timeout ends a hold the application
//! never releases.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{Acceptor, CloseReason, Connection, LogoutHold, OutboundMessage};
use ironfix_session::SessionConfig;
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::codec::Framed;

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

/// Builds a CompID for the test fixtures.
#[track_caller]
fn comp_id(value: &str) -> CompId {
    ok(CompId::new(value), "test CompId must be valid")
}

/// What the application saw, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    /// `from_app` with this MsgType.
    App(String),
    /// `on_peer_logout`.
    PeerLogout,
}

/// Records `from_app` and `on_peer_logout`, and answers the latter with
/// `hold`.
#[derive(Debug)]
struct HoldApp {
    hold: LogoutHold,
    seen: mpsc::UnboundedSender<Seen>,
}

#[async_trait]
impl Application for HoldApp {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {}

    async fn on_logout(&self, _session_id: &SessionId) {}

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
        let _ = self
            .seen
            .send(Seen::App(message.msg_type().as_str().to_string()));
        Ok(())
    }

    async fn on_peer_logout(&self, _session_id: &SessionId) -> LogoutHold {
        let _ = self.seen.send(Seen::PeerLogout);
        self.hold
    }
}

/// Stub-initiator frame builder (CLIENT -> VENUE).
#[track_caller]
fn client_msg(msg_type: &str, seq: u64, extra: &[(u32, &str)]) -> BytesMut {
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, msg_type);
    encoder.put_str(49, "CLIENT");
    encoder.put_str(56, "VENUE");
    encoder.put_uint(34, seq);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    for (tag, value) in extra {
        encoder.put_str(*tag, value);
    }
    let mut frame = BytesMut::new();
    ok(
        encoder.finish_into(&mut frame),
        "test fixture frame must encode",
    );
    frame
}

/// A NewOrderSingle from the stub initiator.
fn order(seq: u64) -> BytesMut {
    client_msg(
        "D",
        seq,
        &[
            (11, "ORD-1"),
            (55, "XYZ"),
            (54, "1"),
            (60, "20261113-10:00:00"),
            (38, "100"),
            (40, "1"),
        ],
    )
}

/// Returns the MsgType (35) of a framed message.
#[track_caller]
fn msg_type_of(frame: &[u8]) -> String {
    let mut decoder = Decoder::new(frame);
    let raw = ok(decoder.decode(), "frame must decode");
    some(raw.get_field_str(35), "frame must carry MsgType (35)").to_string()
}

/// Reads the next frame the acceptor sends that is not a Heartbeat, within
/// 5 s.
async fn next_frame(framed: &mut Framed<TcpStream, FixCodec>) -> String {
    loop {
        let polled = ok(
            timeout(Duration::from_secs(5), framed.next()).await,
            "frame must arrive within 5s",
        );
        let frame = ok(some(polled, "stream must stay open"), "frame must decode");
        let msg_type = msg_type_of(&frame);
        if msg_type != "0" {
            return msg_type;
        }
    }
}

/// Starts an acceptor with `hold_enabled`, its application answering
/// `on_peer_logout` with `hold`, and runs a stub initiator's Logon against
/// it.
async fn establish(
    hold_enabled: bool,
    hold: LogoutHold,
    logout_timeout: Duration,
) -> (
    Framed<TcpStream, FixCodec>,
    Connection,
    mpsc::UnboundedReceiver<Seen>,
) {
    let (seen_tx, seen_rx) = mpsc::unbounded_channel();
    let app = Arc::new(HoldApp {
        hold,
        seen: seen_tx,
    });
    let config = SessionConfig::new(comp_id("VENUE"), comp_id("CLIENT"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
        .with_logout_timeout(logout_timeout);
    let acceptor = Acceptor::new(config, app).with_peer_logout_hold(hold_enabled);
    assert_eq!(acceptor.peer_logout_hold(), hold_enabled);

    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "listener binds");
    let addr = ok(listener.local_addr(), "listener reports its address");
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });

    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    ok(
        framed
            .send(client_msg("A", 1, &[(98, "0"), (108, "30")]))
            .await,
        "client sends its logon",
    );
    assert_eq!(next_frame(&mut framed).await, "A");
    let connection = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), venue).await,
                "handshake within 5s",
            ),
            "venue task joins",
        ),
        "acceptor establishes the session",
    );
    (framed, connection, seen_rx)
}

/// Sends the order and the Logout in one write, as a client closing right
/// after its last order does.
async fn send_order_then_logout(framed: &mut Framed<TcpStream, FixCodec>) {
    ok(framed.feed(order(2)).await, "client queues its order");
    ok(
        framed.feed(client_msg("5", 3, &[])).await,
        "client queues its logout",
    );
    ok(
        SinkExt::<BytesMut>::flush(framed).await,
        "client writes both at once",
    );
}

/// The next thing the application saw, within 5 s.
async fn next_seen(seen: &mut mpsc::UnboundedReceiver<Seen>) -> Seen {
    some(
        ok(
            timeout(Duration::from_secs(5), seen.recv()).await,
            "the application must see it within 5s",
        ),
        "the application must stay alive",
    )
}

/// An execution report for the order.
fn report() -> OutboundMessage {
    let mut report = OutboundMessage::new(MsgType::ExecutionReport);
    report
        .push_str(37, "EX-1")
        .push_str(17, "E-1")
        .push_char(150, '0')
        .push_char(39, '0');
    report
}

/// Without the hold, the Logout is answered at once and `on_peer_logout` is
/// never called: the behaviour before issue #214.
#[tokio::test]
async fn test_without_the_hold_the_logout_is_answered_at_once() {
    let (mut framed, connection, mut seen) =
        establish(false, LogoutHold::Hold, Duration::from_secs(10)).await;
    send_order_then_logout(&mut framed).await;

    assert_eq!(next_frame(&mut framed).await, "5");
    assert_eq!(next_seen(&mut seen).await, Seen::App("D".to_string()));
    connection.wait_closed().await;
    assert!(matches!(
        connection.close_reason(),
        Some(CloseReason::PeerLogout { .. })
    ));
    assert!(
        seen.try_recv().is_err(),
        "on_peer_logout must not run without the hold"
    );
}

/// With the hold, `on_peer_logout` runs after `from_app` has seen the order,
/// a report sent before `reply_logout` is on the wire before the Logout
/// reply, and an application message after the Logout is not delivered.
#[tokio::test]
async fn test_a_report_sent_before_reply_logout_precedes_the_reply() {
    let (mut framed, connection, mut seen) =
        establish(true, LogoutHold::Hold, Duration::from_secs(10)).await;
    send_order_then_logout(&mut framed).await;

    assert_eq!(next_seen(&mut seen).await, Seen::App("D".to_string()));
    assert_eq!(next_seen(&mut seen).await, Seen::PeerLogout);

    // A message after the Logout: logged and consumed, not delivered.
    ok(framed.send(order(4)).await, "client sends after its logout");
    // Nothing is answered while the hold lasts.
    assert!(
        timeout(Duration::from_millis(300), framed.next())
            .await
            .is_err(),
        "the reply must wait for the application"
    );
    assert!(!connection.is_closed());

    ok(
        connection.send(report()).await,
        "the venue sends its report",
    );
    ok(
        connection.reply_logout().await,
        "the venue releases the reply",
    );

    assert_eq!(next_frame(&mut framed).await, "8");
    assert_eq!(next_frame(&mut framed).await, "5");
    connection.wait_closed().await;
    assert!(matches!(
        connection.close_reason(),
        Some(CloseReason::PeerLogout { .. })
    ));
    assert!(
        seen.try_recv().is_err(),
        "the message after the Logout must not reach from_app"
    );
    assert_eq!(connection.next_target_seq(), 5);
}

/// With the hold and an application that returns `Reply`, the Logout is
/// answered once `on_peer_logout` has run.
#[tokio::test]
async fn test_with_the_hold_a_reply_answer_lets_the_reply_go() {
    let (mut framed, connection, mut seen) =
        establish(true, LogoutHold::Reply, Duration::from_secs(10)).await;
    send_order_then_logout(&mut framed).await;

    assert_eq!(next_seen(&mut seen).await, Seen::App("D".to_string()));
    assert_eq!(next_seen(&mut seen).await, Seen::PeerLogout);
    assert_eq!(next_frame(&mut framed).await, "5");
    connection.wait_closed().await;
    assert!(matches!(
        connection.close_reason(),
        Some(CloseReason::PeerLogout { .. })
    ));
}

/// The logout timeout, counted from the Logout's arrival, ends a hold the
/// application never releases.
#[tokio::test]
async fn test_the_logout_timeout_ends_a_hold_never_released() {
    let logout_timeout = Duration::from_secs(1);
    let (mut framed, connection, mut seen) =
        establish(true, LogoutHold::Hold, logout_timeout).await;
    let sent = Instant::now();
    send_order_then_logout(&mut framed).await;

    assert_eq!(next_seen(&mut seen).await, Seen::App("D".to_string()));
    assert_eq!(next_seen(&mut seen).await, Seen::PeerLogout);
    assert_eq!(next_frame(&mut framed).await, "5");
    assert!(
        sent.elapsed() >= logout_timeout,
        "the reply must wait for the logout timeout, went after {:?}",
        sent.elapsed()
    );
    connection.wait_closed().await;
    assert!(matches!(
        connection.close_reason(),
        Some(CloseReason::PeerLogout { .. })
    ));
}
