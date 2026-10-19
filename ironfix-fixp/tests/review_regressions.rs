/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/
//! Regression tests for the FIXP session core review findings on PR #132
//! (issue #95), driven through the public client and server API.
use ironfix_fixp::*;
use std::num::NonZeroUsize;
use std::time::Instant;

const ID: SessionId = SessionId::from_bytes([0x42; 16]);
fn drain(client: &mut FixpClient) -> Vec<Output> {
    std::iter::from_fn(|| client.poll_output()).collect()
}
fn establish(client: &mut FixpClient, now: Instant, next: u64) {
    client.establish(now).expect("establish command");
    let request = drain(client)
        .into_iter()
        .find_map(|o| match o {
            Output::Send(SessionMessage::Establish(m)) => Some(m.timestamp),
            _ => None,
        })
        .expect("Establish emitted");
    client.handle_message(
        &SessionMessage::EstablishmentAck(EstablishmentAck {
            session_id: ID,
            request_timestamp: request,
            keepalive_interval: 5000,
            next_seq_no: Some(next),
        }),
        now,
    );
}
fn client(now: Instant, cfg: FixpConfig) -> FixpClient {
    let anchor = ClockAnchor::new(now, Timestamp::EPOCH);
    let mut client = FixpClient::new(cfg, anchor, ID, FlowType::Idempotent, None);
    client.negotiate(now).expect("negotiate command");
    let request = drain(&mut client)
        .into_iter()
        .find_map(|o| match o {
            Output::Send(SessionMessage::Negotiate(m)) => Some(m.timestamp),
            _ => None,
        })
        .expect("Negotiate emitted");
    client.handle_message(
        &SessionMessage::NegotiationResponse(NegotiationResponse {
            session_id: ID,
            request_timestamp: request,
            server_flow: FlowType::Recoverable,
            credentials: None,
        }),
        now,
    );
    drain(&mut client);
    establish(&mut client, now, 1);
    drain(&mut client);
    client
}
fn requests(outputs: Vec<Output>) -> Vec<RetransmitRequest> {
    outputs
        .into_iter()
        .filter_map(|o| match o {
            Output::Send(SessionMessage::RetransmitRequest(m)) => Some(m),
            _ => None,
        })
        .collect()
}
fn seq(client: &mut FixpClient, now: Instant, next: u64) {
    client.handle_message(
        &SessionMessage::Sequence(Sequence { next_seq_no: next }),
        now,
    );
}
fn replay_one(client: &mut FixpClient, now: Instant, request: RetransmitRequest) {
    client.handle_message(
        &SessionMessage::Retransmission(Retransmission {
            session_id: ID,
            request_timestamp: request.timestamp,
            next_seq_no: request.from_seq_no,
            count: 1,
        }),
        now,
    );
    assert!(matches!(
        client.on_application_message(now),
        Delivery::Accept {
            retransmitted: true,
            ..
        }
    ));
}

#[test]
fn rejected_gap_remains_recoverable_after_reestablishment() {
    let now = Instant::now();
    let cfg = FixpConfig::builder()
        .max_pending_gaps(NonZeroUsize::new(1).expect("one"))
        .build()
        .expect("config");
    let mut client = client(now, cfg);
    seq(&mut client, now, 2); // Missing sequence 1.
    assert_eq!(requests(drain(&mut client))[0].from_seq_no, 1);
    assert!(matches!(
        client.on_application_message(now),
        Delivery::Accept { .. }
    )); // Received 2.
    seq(&mut client, now, 4); // Missing sequence 3 cannot be recorded.
    assert_eq!(client.status(), SessionStatus::Negotiated);
    drain(&mut client);
    client.on_transport_closed();
    drain(&mut client);
    establish(&mut client, now, 4);
    let request = requests(drain(&mut client))
        .into_iter()
        .next()
        .expect("request for first gap");
    assert_eq!(request.from_seq_no, 1);
    replay_one(&mut client, now, request);
    let outputs = drain(&mut client);
    assert!(
        requests(outputs.clone()).iter().any(|r| r.from_seq_no == 3),
        "sequence 3 was forgotten: outputs={outputs:?}, pending={}, next={:?}",
        client.has_pending_recovery(),
        client.next_inbound_seq()
    );
}

#[test]
fn gap_within_capacity_stays_recoverable_after_reestablishment() {
    let now = Instant::now();
    let mut client = client(now, FixpConfig::default());
    seq(&mut client, now, 2);
    drain(&mut client);
    assert!(matches!(
        client.on_application_message(now),
        Delivery::Accept { .. }
    ));
    seq(&mut client, now, 4);
    assert_eq!(client.status(), SessionStatus::Established);
    drain(&mut client);
    client.on_transport_closed();
    drain(&mut client);
    establish(&mut client, now, 4);
    let request = requests(drain(&mut client))
        .into_iter()
        .next()
        .expect("request for first gap");
    assert_eq!(request.from_seq_no, 1);
    replay_one(&mut client, now, request);
    let requests = requests(drain(&mut client));
    assert!(requests.iter().any(|r| r.from_seq_no == 3), "{requests:?}");
}
