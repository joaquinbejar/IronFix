# FIXP Session Operations

What `ironfix-fixp` implements of the FIX Performance Session Layer, what is
tested, and what is not implemented. Every "implemented" row below names the
tests that exercise it; anything not listed as implemented is not.

## Specification and schema

- **Specification:** FIX Performance Session Layer Technical Specification
  **v1.1, Draft Standard, April 18, 2019**, the highest version listed at
  <https://www.fixtrading.org/standards/fixp/> (checked 2026-10-18). v1.0 is
  the April 2021 Technical Standard; its point-to-point chapter says the same
  as v1.1 save for wording and the WebSocket guidance v1.1 adds. Section
  numbers below refer to the v1.1 Draft Standard PDF.
- **Wire format:** the FIXP SBE message schema from
  <https://github.com/FIXTradingCommunity/fixp-specification>,
  `v1-1/resources/SBEschemaForFIXP.xml` at commit `af0e9d7e` (identical to the
  v1.0 Technical Standard's copy): `package="FIXP"`, schema id 2748, version 0,
  little-endian, 19 messages.
- **License:** the specification and schema are © FIX Protocol Ltd., licensed
  CC BY-ND 4.0. The schema and the repository's license are vendored byte for
  byte in `ironfix-fixp/spec/` with a provenance README (git blobs and SHA-256),
  as the input of a conformance test, and are excluded from the published
  package. Nothing is generated from the schema and none of its descriptions is
  reused; the codec is written by hand on `ironsbe-core` 0.7 (`MessageHeader`,
  `VarDataHeader`, `ReadBuffer`, `WriteBuffer`) and checked against it.

## Model

`ironfix-fixp` is a sans-IO core (ADR-0002): `FixpClient` and `FixpServer`
take decoded session messages, application-message arrivals, commands,
transport changes and timer ticks, each with an explicit `Instant`, and queue
`Output`s (messages to write, a transport close, events). It reads no clock:
request timestamps are derived from a `ClockAnchor` the driver supplies. It
does no framing (`ironfix-sofh` does) and stores no application messages (the
driver keeps what it sends and replays the range `retransmit` names). It
depends on `ironfix-core` and `ironsbe-core` only.

States are an explicit enum per role. Every `match` on a state or a message
names its variants; the crate denies `clippy::wildcard_enum_match_arm`.

### Transports

A session has at most one transport at a time. Outputs drained right after
`handle_message` or `on_application_message` belong to the transport that
input came from; outputs of `handle_timeout` and of commands belong to the
transport bound to the session. After `Output::CloseTransport` the session
considers that transport gone: what still arrives on it is reported as
`Event::Ignored` (no second violation, no second close), and `negotiate`,
`establish` and `on_transport_opened` fail with `FixpError::TransportClosing`
until the driver calls `on_transport_closed`. Application messages are
reported the same way, as `Event::Ignored` with the message name
`application message`, both on a closing transport and after the
counterparty's Terminate (section 4.4)
(`test_messages_after_an_unbind_are_ignored_until_the_transport_closes`,
`test_messages_after_a_terminate_are_ignored`,
`test_client_session_messages_before_establishment`,
`test_server_session_messages_before_establishment_are_violations`). A server
session that comes back on a new transport is told with `on_transport_opened`,
which arms the Establish deadline
(`test_server_on_transport_opened_arms_the_establish_deadline`); a server
session left negotiated with no transport has no timer, and evicting it is the
driver's policy: the engine's acceptor drops it with its transport (see
Engine driver).

## Session messages

All 19 messages of the schema encode and decode, round-trip, and match the
schema's template id, block length, field offsets, optional null values and
enumeration values (`codec::tests::test_every_session_message_round_trips`,
`tests/schema_conformance.rs`). How the session handles each:

| Template | Message | Session handling | Tested by |
|---|---|---|---|
| 1 | Negotiate | Client sends it (`negotiate`); server reports it and waits for `accept_negotiation` / `reject_negotiation`; nil session id refused | `test_client_negotiate_sends_negotiate_and_waits`, `test_server_negotiate_waits_for_the_application`, `test_server_rejects_a_nil_session_id` |
| 2 | NegotiationResponse | Server sends it; client matches session id and request timestamp, ignores a mismatch | `test_server_accept_negotiation_answers_and_negotiates`, `test_client_negotiation_response_negotiates`, `test_client_ignores_a_response_for_another_request` |
| 3 | NegotiationReject | Server sends it and closes; client reports it and closes | `test_server_reject_negotiation_closes`, `test_client_negotiation_reject_closes_the_session` |
| 4 | Topic | Multicast only: a protocol violation on a point-to-point session | `test_topic_is_a_violation` |
| 5 | Establish | Client sends it, first time and on re-establishment; server validates it, reports it and waits for `accept_establishment` / `reject_establishment` | `test_client_establish_announces_keepalive_next_seq_and_credentials`, `test_server_accept_establishment_acks_with_its_keepalive_and_next_seq` |
| 6 | EstablishmentAck | Server sends it; client matches it, checks the keepalive range, applies `NextSeqNo` | `test_client_establishment_ack_establishes`, `test_client_ignores_a_mismatched_establishment_answer` |
| 7 | EstablishmentReject | Server sends it (application decision or the automatic codes below); client reports it | `test_server_reject_establishment_keeps_the_session`, `test_client_establishment_reject_keeps_the_session_negotiated` |
| 8 | Sequence | Opens a sequenced run, heartbeat of a sequenced flow; gaps detected on it | `test_send_application_opens_with_a_sequence_then_numbers_implicitly`, `test_heartbeat_of_a_sequenced_flow_is_a_sequence` |
| 9 | Context | Accepted as a Sequence when it names this session; `NextSeqNo` `u64::MAX` (the null value) changes nothing; another session terminates | `test_context_for_this_session_acts_as_a_sequence`, `test_context_with_the_null_next_seq_changes_nothing` |
| 10 | UnsequencedHeartbeat | Heartbeat of an Unsequenced or None flow; a violation on a sequenced flow | `test_heartbeat_of_an_unsequenced_flow_is_an_unsequenced_heartbeat`, `test_unsequenced_heartbeat_on_a_sequenced_flow_is_a_violation` |
| 11 | RetransmitRequest | Sent on a Recoverable inbound gap; validated and served as the provider | see Recoverable flow |
| 12 | Retransmission | Sent per batch by the provider; validated against the request by the requester | see Recoverable flow |
| 13 | RetransmitReject | Sent for refused requests; received, abandons the requested range | see Recoverable flow |
| 14 | Terminate | Both directions; see Termination | see Termination |
| 15 | FinishedSending | Received: answered with FinishedReceiving once everything up to `LastSeqNo` is accounted for; the session is finalized when the binding then ends with a Terminate. Never sent | see Finalization |
| 16 | FinishedReceiving | Sent in answer to FinishedSending, after which this side sends no application message; received, a violation (this side never sends FinishedSending) | see Finalization |
| 17 | Applied | Received: numbered as an application message, reported as `Event::Applied` whatever this side's flow. Never sent by the session | `test_applied_is_reported_and_numbered`, `test_applied_is_reported_whatever_this_side_flow` |
| 18 | NotApplied | Sent on an Idempotent inbound gap; received: numbered, reported, a violation unless this side's flow is Idempotent | see Idempotent flow |
| 19 | MessageTemplate | Accepted at any time and passed over; counts as traffic | `test_message_template_is_accepted_while_established`, `test_client_session_messages_before_establishment` |

## Negotiation and establishment (sections 4.2 and 4.3)

Implemented and tested:

- Client: `negotiate` from idle only; `establish` from negotiated only, first
  time and after any unbinding, announcing the keepalive interval, the
  credentials, and `NextSeqNo` on a sequenced client flow
  (`test_client_negotiate_twice_is_refused`,
  `test_client_establish_requires_a_negotiated_session`,
  `test_client_establish_on_an_unsequenced_flow_sends_no_next_seq`).
- Client: a NegotiationResponse naming both flows None is a violation
  (section 3.4.4.1; `test_client_refuses_a_response_with_both_flows_none`).
- Client: an answer with nothing outstanding, or not matching the session id
  and request timestamp, is ignored with `Event::Ignored` (Appendix A
  7.1.7.5, 7.1.12.8; `test_client_ignores_answers_with_nothing_outstanding`).
- Client: EstablishmentReject `Unnegotiated` closes the client; any other
  code keeps the session negotiated for a retry
  (`test_client_unnegotiated_reject_closes_the_session`).
- Client: an EstablishmentAck keepalive outside the configured range
  terminates (`test_client_terminates_on_a_server_keepalive_out_of_range`);
  a `NextSeqNo` lower than expected on re-establishment terminates (Appendix
  A 7.2.3; `test_client_terminates_on_a_lower_next_seq_at_reestablishment`).
- Server: `accept_negotiation` refuses both flows None and keeps the
  Negotiate pending (`test_server_accept_negotiation_refuses_both_flows_none`).
- Server, automatic EstablishmentReject: `Unnegotiated` for an Establish
  before any negotiation or naming another session (Appendix A 7.1.12.1;
  `test_server_rejects_establish_without_negotiation`,
  `test_server_rejects_establish_for_another_session`); `KeepaliveInterval`
  outside the configured range (Appendix A 7.1.12.4;
  `test_server_rejects_a_keepalive_out_of_range`); `AlreadyEstablished` while
  established (Appendix A 7.1.12.2;
  `test_server_rejects_a_redundant_establish`); `Unspecified` for a
  `NextSeqNo` of zero on a sequenced client flow
  (`test_server_rejects_an_establish_with_next_seq_zero`) or lower than
  expected on re-establishment
  (`test_server_rejects_a_next_seq_that_goes_backwards`).
- Server, automatic NegotiationReject: `DuplicateId` for a second Negotiate
  of the same session, `Unspecified` for another session
  (`test_server_rejects_a_second_negotiate`).
- Server: a Negotiate or Establish arriving while the binding is being
  unbound (this side terminating, or answering the counterparty's Terminate)
  is not answered and is reported as `Event::Ignored`; the client retries on
  a new transport (`test_server_handshake_messages_while_unbinding_are_ignored`).
- Out-of-order handshake messages (a second Negotiate or Establish before the
  first is answered, a role's message sent by the other role) are violations
  (`test_server_out_of_order_handshake_messages_are_violations`,
  `test_server_treats_client_only_messages_as_violations`,
  `test_client_treats_server_only_messages_as_violations`).
- Commands in the wrong state are `FixpError::InvalidState`, with nothing sent
  (`test_server_commands_in_the_wrong_state_are_refused`).
- Handshake timeouts (`handshake_timeout`), each closing the transport:
  client negotiation (closes the client) and establishment (back to
  negotiated, retry on a new transport, Appendix A 7.1.12.9); server waiting
  for Negotiate (closes), for the application's answer to a Negotiate
  (closes) or to an Establish (keeps the session), and for an Establish on a
  transport (keeps the session). A Negotiate or Establish the application
  left unanswered is first refused with NegotiationReject or
  EstablishmentReject `Unspecified` (section 4.2.3, p. 18; section 4.3,
  p. 19; a defect found by #97) (`test_client_negotiation_times_out`,
  `test_client_establishment_times_out_and_can_retry`,
  `test_server_handshake_timeouts`,
  `test_server_application_answers_are_bounded_by_the_handshake_timeout`).
- Re-establishment on a new transport with the sequence numbers carried over
  (sections 3.4.3, 4.1; `test_client_reestablishes_after_the_transport_closes`,
  `test_server_transport_closed_keeps_a_negotiated_session`,
  `tests/loopback.rs`).

## Sequencing (section 3.5)

Implemented and tested:

- Outbound: the first application message after any context switch (binding,
  retransmission batch) is preceded by a Sequence; later ones are numbered
  implicitly (`test_send_application_opens_with_a_sequence_then_numbers_implicitly`,
  `test_gap_on_a_recoverable_flow_is_recovered_end_to_end`).
- Leaving sequenced mode: any session message this side sends other than
  a Sequence (RetransmitRequest, RetransmitReject, FinishedReceiving, a
  Retransmission header) makes the next application message go behind a
  Sequence. This follows Appendix A 7.3.1.1, which reads section 3.5.4
  broadly; a redundant Sequence is only a heartbeat, so the broad reading
  is never wrong on the wire
  (`test_a_retransmit_request_leaves_sequenced_mode`,
  `test_a_retransmit_reject_leaves_sequenced_mode`,
  `test_finished_receiving_leaves_sequenced_mode`,
  `test_one_batch_per_request_provider_is_asked_again` in
  `tests/loopback.rs`).
- Outbound on an Unsequenced flow: no number; on a None flow: refused
  (`test_send_application_on_an_unsequenced_flow_has_no_number`,
  `test_send_application_on_a_none_flow_is_refused`).
- Inbound: the counterparty's numbering starts at the first `NextSeqNo` it
  announces: in its first establishment (Appendix A 7.2.2 and 7.3.1 start at
  100, 200 and 1000), or, if that announced none (sections 4.3.1 and 4.3.2
  allow it), in its first Sequence or Context, since on a stream nothing can
  precede it. Only an application message arriving before any announcement
  takes the fallback 1. From then on an announced number is checked, and a
  higher one is a gap
  (`test_the_first_establishment_sets_where_numbering_starts`,
  `test_without_an_announced_start_the_first_sequence_sets_it`,
  `test_server_takes_the_first_sequence_of_an_unannounced_client_flow`,
  `test_an_application_message_with_no_sequence_is_number_one`,
  `test_inbound_messages_are_numbered_from_the_announced_next_seq`). A
  Sequence equal to the expected number is a heartbeat.
- Inbound violations, each answered with Terminate `UnspecifiedError`: a
  `NextSeqNo` lower than expected (Appendix A 7.3.1.2) or zero; Sequence or
  Context with a number on an Unsequenced or None flow; an application
  message on a None flow (`test_a_lower_next_seq_terminates`,
  `test_a_next_seq_of_zero_terminates`,
  `test_sequence_on_an_unsequenced_flow_is_a_violation`,
  `test_application_message_on_a_none_flow_is_a_violation`).
- Checked arithmetic: the outbound counter stops with
  `FixpError::SequenceExhausted` before reaching the `uint64` null value; an
  inbound counter that would overflow terminates; a single jump above
  `max_gap_len` (default 1 000 000) terminates instead of being requested
  (`test_outbound_sequence_exhaustion_is_a_typed_error`,
  `test_inbound_sequence_overflow_terminates`,
  `test_a_gap_above_max_gap_len_terminates`,
  `test_context_with_the_null_next_seq_changes_nothing`).

## Recoverable flow (section 4.6)

Implemented and tested, as the requester:

- A gap on the counterparty's Recoverable flow is reported
  (`Event::SequenceGap`) and requested; messages after the gap are accepted
  meanwhile and `has_pending_recovery` is true; retransmitted messages are
  delivered as `retransmitted`; `Event::RecoveryComplete` when no gap remains
  (`test_gap_on_a_recoverable_flow_is_recovered_end_to_end`).
- One RetransmitRequest in flight at a time (section 4.6.1;
  `test_only_one_retransmit_request_is_in_flight`).
- Requests cut to `max_retransmit_count`, each with its own timestamp
  (`test_a_large_gap_is_requested_in_chunks`).
- Paced answers in several batches, with real-time messages between them
  (section 4.6.2.2, Appendix A 7.3.4.2;
  `test_a_paced_retransmission_may_interleave_real_time_messages`).
- A Retransmission that answers no request, another request, starts at the
  wrong number, or carries more than remains, or any Retransmission on a flow
  that is not Recoverable (Appendix A 7.3.4), terminates
  (`test_retransmission_outside_a_request_terminates`).
- RetransmitReject abandons the requested range (`Event::RetransmitRejected`);
  one for another request is ignored
  (`test_retransmit_reject_abandons_the_requested_range`).
- A request with no retransmitted message for `retransmit_timeout` is
  reported once (`Event::RetransmitTimedOut`) and handled by
  `RetransmitStallPolicy`:
  - `ReRequestAfterContextSwitch`, the default: asks again for what is still
    missing only `retransmit_timeout` after a Sequence or Context cut the
    last batch short of its Count (section 3.5.4), otherwise waits. A cut
    that arrives after the stall was reported restarts the timer from the
    cut, so the request is still made and later gaps are not blocked (the
    case where the provider's heartbeat interval is at least
    `retransmit_timeout`). Against IronFix's own provider pacing its batches
    more slowly than `retransmit_timeout`, no premature second request is
    sent and the provider does not terminate
    (`test_default_stall_policy_waits_for_a_paced_ironfix_provider`,
    `test_default_stall_policy_asks_again_after_an_interrupted_batch`,
    `test_default_stall_policy_asks_again_when_the_cut_follows_the_stall`).
  - `ReRequestAfterBatch`: everything the default does, and also asks
    again `retransmit_timeout` after a batch that arrived in full while the
    request is still short of its `Count`, for a provider that serves one
    batch per request (section 4.6.2.2). A batch still short of its own
    `Count` is waited for. Against a provider pacing several batches for
    one request more slowly than `retransmit_timeout`, the new request is
    premature and a strict provider terminates with `ReRequestInProgress`
    (`test_after_batch_stall_policy_asks_again_after_a_complete_short_batch`,
    `test_after_batch_stall_policy_waits_while_a_batch_is_incomplete`,
    `test_one_batch_per_request_provider_is_asked_again` in
    `tests/loopback.rs`).
  - `EventOnly`: never asks again (`test_event_only_stall_policy_never_asks_again`).
  - `Terminate`: terminates with `UnspecifiedError`; the gap is requested
    again after re-establishment, when no retransmission can be in progress
    (`test_terminate_stall_policy_unbinds_and_asks_again_after_reestablishment`).
  - Residual risk, documented on the enum: a provider that cut a batch short
    but still considers its request in progress sees the default policy's
    new request as premature, and a strict one terminates with
    `ReRequestInProgress`; a provider that answers with one complete short
    batch and expects a new request is never asked again under the default
    (use `ReRequestAfterBatch` with it).
- At most `max_pending_gaps` separate gaps; one more terminates
  (`test_too_many_unrecovered_gaps_terminate`).
- Unrecovered gaps survive the transport and are requested again after
  re-establishment; the EstablishmentAck's `NextSeqNo` reveals messages lost
  with the connection (section 4.3.2;
  `test_unrecovered_gaps_are_requested_again_after_reestablishment`,
  `tests/loopback.rs`).

Implemented and tested, as the provider:

- A valid request is reported (`Event::RetransmitRequested`) and answered with
  `retransmit` batches, each queuing a Retransmission header and returning the
  range to replay; `reject_retransmit_request` and `end_retransmission`
  (`test_provider_answers_in_batches`,
  `test_provider_can_reject_or_end_a_request`).
- Automatic RetransmitReject: `InvalidSession` (another session id),
  `RequestLimitExceeded` (above `max_retransmit_count`), `OutOfRange` (zero
  count, `FromSeqNo` 0, numbers not yet sent, overflowing range)
  (section 4.6.2.3, Appendix A 7.3.5;
  `test_provider_refuses_invalid_requests_with_the_right_code`).
- A request while one is being answered terminates with
  `ReRequestInProgress` (sections 4.6.4, 6.3; Appendix A 7.3.4.1;
  `test_a_request_while_one_is_answered_terminates_with_re_request_in_progress`).
- A request to a flow that is not Recoverable terminates (section 4.6.1;
  `test_a_request_to_a_flow_that_is_not_recoverable_terminates`).

## Idempotent flow (section 4.8)

Implemented and tested:

- A gap on the counterparty's Idempotent flow sends NotApplied as an
  application message of this side's flow (`Output::SendApplication`, which
  consumes a sequence number), behind a Sequence when needed, and keeps
  accepting (`test_gap_on_an_idempotent_flow_sends_not_applied`).
- On an Unsequenced return flow NotApplied carries no number; on a None
  return flow it is not sent and the gap is only reported
  (`test_not_applied_on_an_unsequenced_return_flow_has_no_number`,
  `test_gap_without_a_return_flow_is_only_reported`).
- A gap too large for NotApplied's 32-bit `Count` terminates (reachable only
  with `max_gap_len` raised above it;
  `test_a_gap_too_large_for_not_applied_terminates`).
- NotApplied received for this side's flow when it is not Idempotent
  terminates (`test_not_applied_for_a_recoverable_flow_is_a_violation`).
  Applied is not checked that way: FIXP names no violation for it
  (sections 4.8.1, 6.3).

## Keepalive (section 4.5)

Implemented and tested:

- A heartbeat (Sequence on a sequenced flow, UnsequencedHeartbeat otherwise)
  whenever this side's keepalive interval passes without an application
  message (`test_heartbeat_of_a_sequenced_flow_is_a_sequence`,
  `test_application_traffic_defers_the_heartbeat`).
- Termination (`Event::KeepaliveLapsed`, Terminate `UnspecifiedError`, close)
  when the counterparty sends nothing for its keepalive interval plus the
  grace, which defaults to the interval itself and is configurable
  (`test_peer_silence_terminates_after_its_interval_plus_grace`,
  `test_peer_silence_grace_is_configurable`).
- The counterparty's interval is bounded by the configured range, so it
  cannot disable dead-peer detection, and every timer setting is bounded by
  `MAX_TIMER` (`u32::MAX` ms), so no deadline overflows and never fires
  (`config::tests::test_builder_rejects_timers_above_the_wire_range`).

## Termination (section 4.4)

Implemented and tested:

- `terminate(Finished)` waits for the counterparty's Terminate, then asks for
  the transport to close; without an answer within the keepalive interval it
  closes anyway (sections 4.4.1, 4.4.2;
  `test_graceful_terminate_waits_for_the_answer`,
  `test_terminating_gives_up_after_a_keepalive_interval`).
- While it waits, in-flight messages are still numbered, a retransmission
  batch already arriving included, but nothing more is sent: no new
  RetransmitRequest, and the retransmission this side was serving ends
  (`test_in_flight_messages_are_processed_while_terminating`,
  `test_terminate_during_a_retransmission_batch_keeps_its_numbers`,
  `test_terminate_answered_mid_batch_requests_the_rest_after_reestablishment`).
- Any other code closes at once (Appendix A 7.2.1;
  `test_an_error_terminate_closes_at_once`).
- A counterparty Terminate is answered with Terminate `Finished`, after which
  everything received is reported as `Event::Ignored`; the responder closes
  the transport only if the initiator has not within the keepalive interval
  (`test_messages_after_a_terminate_are_ignored`).
- A Terminate naming another session is a violation
  (`test_terminate_for_another_session_is_a_violation`).
- The logical session survives every unbinding; it can be established again.

## Finalization (section 4.7)

Implemented and tested, receiving side only (sections 4.7.1, 4.7.2, 6.3):

- A counterparty's FinishedSending is reported
  (`Event::PeerFinishedSending`) and answered with FinishedReceiving once
  every message up to its `LastSeqNo` is accounted for, after which this side
  waits for the counterparty's Terminate
  (`test_finished_sending_is_answered_then_the_terminate_awaited`,
  `test_finished_sending_then_terminate_ends_the_binding_gracefully`).
- A `LastSeqNo` past what arrived is a gap: requested on a Recoverable flow,
  with FinishedReceiving sent after the recovery (Appendix A 7.4.3), reported
  with NotApplied on an Idempotent one
  (`test_finished_sending_with_a_gap_is_answered_after_recovery`,
  `test_finished_sending_on_an_idempotent_flow_reports_the_gap_then_answers`).
- A repeated FinishedSending (its heartbeat role, section 4.7.1) gets no
  second answer (Appendix A 7.4.2); an application message after it is a
  violation (section 6.3).
- After FinishedReceiving this side sends no application message:
  `send_application` returns `FixpError::FinishedReceivingSent`, with
  nothing queued and no number spent. Section 6.3 forbids it for the
  responder; the half-close of Appendix A 7.4.1 and 7.4.6 (informative) is
  declined, and per section 4.7.2 such a message would likely be lost to
  the counterparty's Terminate. Before FinishedReceiving goes out (a gap
  still being recovered) sending is allowed
  (`test_no_application_message_after_finished_receiving`).
- A RetransmitReject that gives up part of the range up to `LastSeqNo` is
  not a violation: FinishedReceiving still goes out, after
  `Event::RetransmitRejected` has reported the loss, since nothing more can
  be recovered and the counterparty would otherwise repeat FinishedSending
  for ever
  (`test_finished_receiving_after_a_retransmit_reject_follows_the_reported_loss`).
- Finalized sessions (section 4.7.2): once FinishedReceiving has gone out,
  the binding ending with a graceful Terminate exchange (a counterparty
  Terminate with code `Finished` answered, or this side's `Finished`
  answered with `Finished`) finalizes the logical session; an error
  Terminate in either direction does not. This code check is local policy
  (see the decisions table)
  (`test_an_error_terminate_after_finished_receiving_does_not_finalize`,
  `test_an_error_answer_to_our_finished_terminate_does_not_finalize`). When the binding is over (the transport reported closed, or the
  closing deadline passed) the role reports `Event::SessionFinalized` and
  moves to `SessionStatus::Finalized`, which accepts no command: the client
  refuses `establish`, and the server keeps the identifier
  (`session_id()`), refuses `on_transport_opened`, answers an Establish for
  it with EstablishmentReject `Unnegotiated` and a Negotiate for it with
  NegotiationReject `DuplicateId`, each a protocol violation that closes
  the transport (section 6.3). A binding that ends any other way (a
  transport failure, an error Terminate, this side's Terminate going
  unanswered) does not finalize: the counterparty may come back to finish
  (`test_a_finalized_client_cannot_establish_again`,
  `test_a_finalized_client_is_marked_when_its_closing_deadline_lapses`,
  `test_a_finalized_server_refuses_the_session_id`).
- After it, a Sequence or Context announcing numbers past `LastSeqNo`
  terminates (section 6.3, Appendix A 7.4.5) and no gap is opened for
  numbers the counterparty never sent; one equal to `LastSeqNo + 1`
  announces nothing new and is accepted
  (`test_no_next_seq_past_last_seq_no_after_finished_sending`).
- Violations: FinishedReceiving (this side never sent FinishedSending), no
  `LastSeqNo` on a sequenced flow, a `LastSeqNo` below what already arrived,
  another session (`test_invalid_finalization_messages_are_violations`). On
  an Unsequenced flow `LastSeqNo` is not needed
  (`test_finished_sending_on_an_unsequenced_flow_needs_no_last_seq`).

## Untrusted input

Implemented and tested:

- Every malformed message is a typed `FixpDecodeError`: truncated at any byte,
  a block shorter than the schema's, a block or variable-length field longer
  than the input, an unknown template, another schema, an undefined
  enumeration value, a reason that is not UTF-8
  (`test_decode_rejects_every_truncation_of_every_message` and the other
  `codec::tests::test_decode_rejects_*`).
- No input panics the decoder (`test_decode_never_panics_on_arbitrary_bytes`
  sweeps every template id, block length 0 to 40 and body length 0 to 64), and
  nothing is copied beyond the bytes present. The length `decode` returns
  covers the header, the declared root block and the schema version 0
  variable-length fields.
- A longer block from a newer schema version is accepted and skipped
  (`test_decode_skips_a_longer_block_from_a_newer_schema_version`).
- Credentials never appear in `Debug` output, and a test captures every
  `tracing` line both roles emit through a handshake with credentials both
  ways, a violation and a termination, and finds none of them
  (`test_credentials_debug_never_shows_the_secret`,
  `test_client_debug_never_shows_credentials`,
  `test_tracing_output_never_contains_credentials`, `tests/loopback.rs`).

## Decisions where the specification is open or inconsistent

Page numbers are the printed pages of the [v1.1 Draft Standard PDF](https://github.com/FIXTradingCommunity/fixp-specification/blob/master/v1-1/doc/publication/FIXP-Technical-Draft-Standard-v1.1.pdf).

| Topic | Specification | Decision |
|---|---|---|
| RetransmitRequest for numbers not yet sent | 4.6.2.3 and Appendix A 7.3.5: RetransmitReject `OutOfRange`; 6.3: a violation | RetransmitReject `OutOfRange`; a zero `Count` too |
| Code of the answer to a Terminate | 4.4.1 says to answer, not with which code | `Finished` |
| `NextSeqNo` lower than expected | Appendix A 7.2.2, 7.2.3, 7.3.1.2 (informative) | Terminate `UnspecifiedError`; a server refuses such an Establish with `Unspecified` instead |
| Where numbering starts | 5.1.1 (multicast) and Appendix A 7.1.8 start at 1; Appendix A 7.2.2 and 7.3.1 start at 100, 200, 1000; 4.3.1 and 4.3.2 limit when an establishment announces it | The first `NextSeqNo` announced (establishment, else first Sequence or Context); 1 only if an application message comes first |
| A Sequence after FinishedSending | Appendix A 7.4.5 terminates on one after FinishedReceiving | Terminate if it announces numbers past `LastSeqNo`; accept `LastSeqNo + 1`, which announces nothing new |
| Stalled RetransmitRequest | 4.6.2.2: asking again is "the requester's responsibility"; 4.6.1, 4.6.4, 6.3: no second request while one is in progress | `RetransmitStallPolicy`, default: ask again only after a context switch cut a batch short |
| After a RetransmitReject | Not specified | The range is abandoned and reported |
| Leniency on the counterparty's silence | 4.4: "some leniency" | Grace equal to its interval by default (configurable, at most `MAX_TIMER`) |
| Size of a gap | Not bounded | `max_gap_len`, default 1 000 000; a larger jump terminates |
| Session id validity | 3.4.1: a version 4 UUID; Appendix A 7.1.7.3 refuses all zeros | Only the nil UUID is refused |
| NotApplied when this side's flow is None | Not specified | Not sent; the gap is reported as an event |
| Applied on a flow that is not Idempotent | 4.8.2 makes NotApplied a violation there; nothing is said of Applied | Reported, not checked |
| Context `NextSeqNo` | Optional in 3.5.3, required in the schema | Required on the wire; `u64::MAX`, the SBE null, means "no number" |
| `NextSeqNo` in Establish on an Idempotent flow | 4.3.1: "re-establishment of a recoverable flow only"; Appendix A 7.1.10 sends it | Sent on every sequenced flow, first establishment included |
| `FinishedSending` without `LastSeqNo` on a sequenced flow | 4.7.1: it must be populated | A protocol violation |
| Application messages after FinishedReceiving | 6.3 (p. 39) forbids them for the responder; Appendix A 7.4.1 (p. 69, informative) shows a half-close; 4.7.2 (p. 31): they are likely lost | Refused with `FixpError::FinishedReceivingSent`; the normative 6.3 takes precedence over the informative appendix |
| A provider serving one batch per request | 4.6.2.2 (p. 28) allows several batches per request and makes asking for the remainder the requester's responsibility; 6.3 (p. 39) forbids overlapping requests, hence the pacing trade-off | Opt-in `RetransmitStallPolicy::ReRequestAfterBatch`; the default still waits |
| FinishedReceiving after a RetransmitReject | 4.6.2.3 and 4.7.2 (p. 31) neither mandate nor forbid it | **Local policy**: sent, after the loss is reported by `Event::RetransmitRejected`; not a violation |
| When a session is finalized | 4.7.2 (p. 31; [text](https://github.com/FIXTradingCommunity/fixp-specification/blob/master/v1-1/doc/04PointToPointSessionProtocol.md)): FinishedReceiving, then unbinding; no exception by Terminate code | **Local policy**, conservative, not a check the specification mandates: finalized only when every Terminate of the closing exchange carries `Finished` (the counterparty's, or this side's and its answer) after this side sent FinishedReceiving. An error Terminate either way, or a transport failure, leaves the session negotiated |
| Re-establishing or renegotiating a finalized identifier | 6.3: a violation | Server: EstablishmentReject `Unnegotiated` or NegotiationReject `DuplicateId`, then the transport closed; client: `establish` refused locally |
| Leaving sequenced mode | 3.5.4 names a context switch; Appendix A 7.3.1.1 (p. 56): any session message | Any session message this side sends other than a Sequence |
| A handshake request the server cannot decide | 4.2.3 (p. 18): a server "must send NegotiationReject"; 4.3 (p. 19): the response to Establish is EstablishmentAck or EstablishmentReject | Always answered before the close: NegotiationReject `FlowTypeNotSupported` when the application accepts with both flows None, otherwise `Unspecified` (a decision that panicked or lapsed); EstablishmentReject `Unspecified`. The codes are **local policy** |
| Transport after an automatic EstablishmentReject | 6.3 (p. 39): an Establish without negotiation "should" end the session; Appendix A 7.1.12 (p. 45 to 48) shows the reject and no close | **Local policy**: the transport stays open for a retry on it, bounded by `handshake_timeout`; a reject decided by the application closes it at once |
| Routing a frame to the session or the application | 3.3 (p. 12): left to the encoding supplements; SOFH lets encodings mix | **Local policy**: SOFH SBE 1.0 little-endian whose SBE header names schema 2748 is a session message; anything else, an unregistered encoding type included, is an application message |

## Engine driver (`ironfix-engine`, `fixp` feature)

`ironfix_engine::fixp` composes the core with `ironfix-sofh` over a stream
(issue #96, ADR-0003). The feature is off by default; with it off, neither
`ironfix-sofh`, `ironfix-fixp` nor `ironsbe-core` is in the engine's normal
dependency graph (`make check-fixp-deps`, run in CI).

- **Entry points.** `FixpInitiator::connect` (TCP, `TCP_NODELAY`) or
  `connect_stream` (any `AsyncRead + AsyncWrite`, a TLS stream included)
  negotiates and establishes (sections 4.2, 4.3) and returns a
  `FixpConnection` once established. `FixpAcceptor::serve` (a listener) or
  `accept_stream` runs the server side; `FixpApplication::on_negotiate`
  and `on_establish` receive the request with its credentials and decide.
  The default `on_negotiate` refuses (`Credentials`).
- **One task per transport.** A driver task reads SOFH frames, takes
  `FixpConnection` commands and sleeps until the core's `poll_timeout`,
  feeding each input to the core with tokio's clock and carrying out the
  outputs in order. It ends on end of stream, an I/O, framing or write
  timeout error, or the core's `CloseTransport`; it then reports the
  transport closed to the core, hands the last events to the application,
  and signals `FixpConnection::wait_closed`.
- **No self-deadlock.** Outbound frames go to a buffer the driver writes
  out in the same `select` as its reads, so a pending write never stops
  reading (two sides writing at once over a tiny transport both progress);
  the buffer is bounded (commands pause above 1 MiB, the transport closes
  above 16 MiB, `write_timeout` bounds a write that makes no progress).
  `on_established`, `on_message`, `on_event` and `on_closed` run in order in
  a callback task, so they may await their own `FixpConnection`; inbound
  reads pause while more than 1024 callbacks wait. `on_negotiate` and
  `on_establish` run in a task of their own while the driver keeps reading
  and running the core's handshake deadline: a lapse (section 4.2,
  `handshake_timeout`) or a disconnect while one is pending closes the
  transport and releases the identifier in the acceptor. A request left
  undecided (a lapse, a decision task that panicked, an acceptance the core
  refuses such as two None flows) is answered with NegotiationReject or
  EstablishmentReject before the close (sections 4.2.3 and 4.3).
- **Routing.** A frame with SOFH encoding type SBE 1.0 little-endian
  (`0xEB50`) whose SBE header names schema 2748 is a session message; any
  other frame is an application message, passed to the core's
  `on_application_message` and, when accepted, to
  `FixpApplication::on_message` with its sequence number, retransmitted
  flag, encoding type and bytes. Decoding business messages is the
  application's job. Sending a payload that names schema 2748 is refused
  (`FixpEngineError::ReservedSchema`), as is one above the frame ceiling,
  both before a sequence number is spent.
- **Retransmission as the provider** (section 4.6.2). On a Recoverable
  outbound flow the driver keeps the last `DEFAULT_RETRANSMIT_CAPACITY`
  (10 000, a setting) application messages, NotApplied included, by
  sequence number. A RetransmitRequest the core validated is answered in
  one batch: the Retransmission header, then the stored frames. A range no
  longer fully kept is refused with RetransmitReject `OutOfRange`
  (section 4.6.2.3); this is local policy, the specification names the
  code for numbers not sent.
- **Finalized identifiers** (sections 4.7.2, 6.3). The core records
  finalization in its role instance, which lives as long as its transport.
  `FixpAcceptor` therefore remembers, for its own lifetime and in memory,
  the identifiers live on one of its transports and those finalized, and
  answers a Negotiate naming either with NegotiationReject `DuplicateId`.
- **Untrusted input.** A SOFH error closes the transport (every SOFH error
  is fatal). A frame naming schema 2748 that does not decode is a protocol
  violation (section 6.3): Terminate `UnspecifiedError` once established,
  otherwise the transport is closed. Neither panics.
- **Credentials** reach the application in `NegotiateRequest` and
  `EstablishRequest`; every engine type holding them prints their length
  only, and a test captures every `tracing` line of both roles through a
  handshake with credentials and finds none of the bytes.

Tested in `ironfix-engine/tests/fixp_tests.rs`: engine against engine over
TCP and over an in-memory duplex (negotiate, establish, application messages
both ways, Terminate); engine against a hand-driven core in both roles, as
the requester of a retransmission (a gap revealed by a Sequence) and as its
provider, over TCP and duplex; a request for messages no longer kept; a
finalized identifier refused on a new transport; a malformed session
message; a reserved-schema and an oversized payload; the credentials log
check; callbacks awaiting their own connection in both roles; bilateral
sends over a 64-byte duplex; and a negotiate or establish decision that
never returns, or a disconnect while one is pending, releasing the
identifier.

Not done by the driver: re-establishing an unbound session on a new
transport (each binding is its own task, and the client is consumed by
`connect`), evicting idle negotiated sessions (the acceptor drops them with
their transport), and persisting sequence numbers or sent messages.

## Conformance suite (issue #97)

`ironfix-engine/tests/fixp_conformance_tests.rs` (`fixp` feature) runs the
engine, in both roles, against a **raw peer**: SOFH headers and FIXP SBE
session messages built byte by byte from the schema, and the engine's frames
parsed the same way, over a real TCP socket. It uses neither `SofhCodec` nor
the `ironfix-fixp` codec, so IronFix is not tested against itself. Each test
cites the section and printed page of the v1.1 Draft Standard; "policy"
marks a case the specification leaves open or only shows in the informative
Appendix A (see the decisions table). Every wait is bounded (5 s) and the
timers involved are configured an order of magnitude below it.

| Behaviour | FIXP v1.1 | Kind | Test(s) |
|---|---|---|---|
| SOFH length above the ceiling closes the transport, before and after establishment | 3.3.3 (p. 12), 4.4 (p. 22) | spec | `test_server_closes_on_an_oversized_sofh_length`, `test_client_closes_on_an_oversized_sofh_length_when_established` |
| SOFH length below the 7-byte minimum closes | 3.3.3 (p. 12), 4.4 (p. 22) | spec | `test_server_closes_on_a_sofh_length_below_the_header` |
| Frames split byte by byte, and coalesced in one write | 3.3.3 (p. 12) | spec | `test_server_reassembles_a_frame_split_into_single_bytes`, `test_server_splits_coalesced_frames` |
| Unknown SOFH encoding type: an application message once established, a violation before | 3.3 (p. 12), 6.3 (p. 39) | policy (routing) | `test_server_delivers_an_unknown_encoding_type_as_an_application_message`, `test_server_refuses_an_unknown_encoding_type_before_establishment` |
| Truncated SBE session message: Terminate once established, close before; unknown template | 4.4 (p. 22), 6.3 (p. 39), 3.3.1 (p. 12) | spec | `test_server_terminates_on_a_truncated_session_message`, `test_server_closes_on_a_truncated_negotiate`, `test_client_closes_on_a_truncated_negotiation_response`, `test_client_terminates_on_an_unknown_session_template` |
| Negotiate and Establish fields sent; NegotiationResponse and EstablishmentAck fields answered | 4.2.1, 4.2.2 (p. 17 to 18), 4.3.1, 4.3.2 (p. 20 to 21) | spec | `test_client_handshake_fields`, `test_server_handshake_fields` |
| Every NegotiationRejectCode, received and sent; `DuplicateId` for a live id; nil id | 4.2.3 (p. 18 to 19), 3.4.1 (p. 13) | spec (nil id: Appendix A 7.1.7.3) | `test_client_reports_every_negotiation_reject_code`, `test_server_sends_every_negotiation_reject_code`, `test_server_rejects_a_live_session_id_with_duplicate_id`, `test_server_rejects_a_nil_session_id` |
| Every EstablishmentRejectCode received; `SessionBlocked`, `Credentials`, `Unnegotiated`, `AlreadyEstablished`, `KeepaliveInterval`, `Unspecified` sent | 4.3.3 (p. 21) | spec (`Unspecified` for `NextSeqNo` 0: policy) | `test_client_reports_every_establishment_reject_code`, `test_server_sends_application_establishment_reject_codes`, `test_server_rejects_an_establish_without_negotiation`, `test_server_rejects_a_redundant_establish`, `test_server_rejects_a_keepalive_out_of_range`, `test_server_rejects_a_next_seq_no_of_zero_with_unspecified` |
| Establish before the NegotiationResponse; application message before establishment | 6.3 (p. 39) | spec | `test_server_refuses_an_establish_sent_before_the_negotiation_response`, `test_server_refuses_an_application_message_before_establishment` |
| A refused or undecided Negotiate or Establish is answered with a reject (defect fixed by #97) | 4.2.3 (p. 18), 4.3 (p. 19) | spec (codes: policy) | `test_server_rejects_a_negotiation_with_both_flows_none`, `test_server_rejects_a_negotiation_when_the_application_fails`, `test_server_rejects_a_negotiation_not_answered_in_time`, `test_server_rejects_an_establishment_when_the_application_fails`, `test_server_rejects_an_establishment_not_answered_in_time` |
| Handshake timeouts; a response for another request ignored; transport after an automatic reject | 4.3.1 (p. 20), Appendix A 7.1.7.5 (p. 43) | policy | `test_client_negotiation_times_out`, `test_client_establishment_times_out`, `test_server_closes_a_silent_transport_after_the_handshake_timeout`, `test_client_ignores_a_negotiation_response_for_another_request`, `test_server_bounds_the_transport_after_an_unnegotiated_establish` |
| Both flows None refused; keepalive outside the agreed range | 3.4.4.1 (p. 14), 4.3.1 (p. 20) | spec / policy (range) | `test_client_refuses_both_flows_none`, `test_client_terminates_on_a_server_keepalive_out_of_range` |
| Implicit numbering after Sequence; numbering from the announced `NextSeqNo`; Context for this session | 3.5.1 (p. 14), 4.3.2 (p. 20), 3.5.3 (p. 15) | spec | `test_server_numbers_messages_after_a_sequence`, `test_client_numbers_from_the_announced_next_seq_no`, `test_server_accepts_a_context_for_its_session` |
| Lower `NextSeqNo`; jump above `max_gap_len` (no overflow at `u64::MAX`); Context for another session | Appendix A 7.3.1.2 (p. 56 to 57), 3.5.3 (p. 15) | policy | `test_server_terminates_on_a_lower_next_seq_no`, `test_server_terminates_on_a_sequence_jump_above_the_gap_bound`, `test_server_terminates_on_a_context_for_another_session` |
| Recoverable gap: RetransmitRequest, Retransmission delivered as retransmitted, real time resumes behind a Sequence | 4.6.1 (p. 26), 4.6.2 (p. 26 to 27), 3.5.4 (p. 15) | spec | `test_server_requests_and_receives_a_retransmission`, `test_client_requests_and_receives_a_retransmission` |
| One RetransmitRequest in flight | 4.6.1 (p. 26) | spec | `test_server_keeps_one_retransmit_request_in_flight` |
| Every RetransmitRejectCode received abandons the range | 4.6.2.3 (p. 28) | spec | `test_server_reports_every_retransmit_reject_code`, `test_client_reports_a_retransmit_reject` |
| Provider: Retransmission header then the same frames; every RetransmitRejectCode sent; overflowing and empty ranges; messages no longer kept | 4.6.2 (p. 26 to 27), 4.6.2.3 (p. 28) | spec (empty range, eviction: policy) | `test_server_serves_a_retransmission`, `test_client_serves_a_retransmission`, `test_server_sends_every_retransmit_reject_code`, `test_server_rejects_overflowing_and_empty_retransmit_requests`, `test_client_rejects_a_request_for_messages_no_longer_kept` |
| RetransmitRequest to a flow that is not Recoverable; Retransmission with no request | 4.6.1 (p. 26), Appendix A 7.3.4 (p. 60 to 63) | spec / policy (code) | `test_server_terminates_on_a_retransmit_request_to_a_flow_that_is_not_recoverable`, `test_client_terminates_on_an_unsolicited_retransmission` |
| Idempotent gap answered with NotApplied behind a Sequence; Applied and NotApplied received; NotApplied for a Recoverable flow | 4.8.1, 4.8.2 (p. 33) | spec | `test_server_sends_not_applied_on_an_idempotent_gap`, `test_client_sends_not_applied_on_an_idempotent_gap`, `test_client_reports_applied_and_not_applied`, `test_client_terminates_on_not_applied_for_a_recoverable_flow` |
| Unsequenced and None flows: no numbers, Sequence or Context refused, no application message on None; Topic refused | 3.5.1 (p. 14), 3.4.4 (p. 14), 6.1 (p. 38), 6.3 (p. 39) | spec | `test_server_unsequenced_flow_has_no_numbers_and_refuses_a_sequence`, `test_server_none_flow_refuses_a_context`, `test_server_terminates_on_an_application_message_on_a_none_flow`, `test_client_terminates_on_a_topic`, `test_server_terminates_on_a_server_only_message` |
| Heartbeat: Sequence on a sequenced flow, UnsequencedHeartbeat otherwise | 4.5 (p. 25 to 26) | spec | `test_server_heartbeats_with_a_sequence`, `test_client_heartbeats_with_an_unsequenced_heartbeat` |
| Peer silence terminates; a heartbeating peer does not | 4.5 (p. 25), 4.4 (p. 22) | spec (grace: policy) | `test_server_terminates_a_silent_client`, `test_client_terminates_a_silent_server_but_not_a_heartbeating_one` |
| Every TerminationCode received is answered with Terminate `Finished` | 4.4.1 (p. 23) | spec (answer code: policy) | `test_server_answers_every_terminate_code`, `test_client_answers_a_terminate` |
| Orderly terminate; unanswered terminate closes; nothing sent after Terminate; messages after the peer's Terminate ignored; abrupt disconnect | 4.4 (p. 22), 4.4.1, 4.4.2 (p. 23) | spec | `test_client_orderly_terminate`, `test_server_closes_when_its_terminate_is_not_answered`, `test_server_sends_nothing_after_its_terminate`, `test_server_ignores_messages_after_the_peer_terminate`, `test_abrupt_disconnect_in_both_roles` |
| Terminate for another session | 4.4 (p. 22) | policy | `test_server_terminates_on_a_terminate_for_another_session` |
| Finalization started by the peer: FinishedReceiving, no application message after it, finalized id refused; recovery up to `LastSeqNo` first; repeated FinishedSending answered once; Unsequenced flow | 4.7.1, 4.7.2 (p. 31), 6.3 (p. 39), 3.4.1 (p. 13) | spec (finalize only on `Finished`: policy) | `test_server_finalization_and_reuse_refused`, `test_client_recovers_up_to_last_seq_no_before_finished_receiving`, `test_server_answers_finished_sending_once`, `test_server_answers_finished_sending_on_an_unsequenced_flow` |
| Finalization violations: unsolicited FinishedReceiving, application message after FinishedSending, no `LastSeqNo` on a sequenced flow | 6.3 (p. 39), 4.7.1 (p. 31) | spec / policy (missing `LastSeqNo`) | `test_server_terminates_on_an_unsolicited_finished_receiving`, `test_client_terminates_on_an_application_message_after_finished_sending`, `test_server_terminates_on_finished_sending_without_last_seq_no` |

Not exercised against the engine, and why:

- **Terminate `ReRequestInProgress` sent by the engine** (4.6.4, p. 29):
  the engine provider answers a request in one batch at once, so no request
  can arrive while one is in progress. The core sends it
  (`test_a_request_while_one_is_answered_terminates_with_re_request_in_progress`).
- **FinishedSending sent by the engine** (4.7.1): not implemented (see Not
  implemented).
- **Re-establishment on a new transport** (3.4.3, 4.1): not driven by the
  engine (see Engine driver); the core and `tests/loopback.rs` cover it.
- **Multiplexing, datagrams, multicast, WebSocket**: not implemented.

## Not implemented

- **Sending a finalization** (section 4.7): this side never sends
  FinishedSending, so it never starts the finalization of a logical
  session. Finalization started by the counterparty is answered and
  recorded (see Finalization).
- **Multiplexing** (section 3.5.3): one session per transport.
- **Datagram transports** (section 3.5.2): a stream is assumed; no Sequence at
  the start of each datagram.
- **Multicast** (section 5), **WebSocket** (section 4.9), and applying
  in-band templates (section 3.6).
- **Session-layer persistence**: sequence numbers and gaps live in memory; a
  restarted process cannot re-establish a session.
- **Application-message storage**: the driver's job.
- **Engine re-establishment and persistence**: the engine driver (below)
  runs one binding per transport; it does not re-establish an unbound
  session on a new transport, and keeps sent messages in memory only.
