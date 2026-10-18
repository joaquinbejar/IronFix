# FIXP Session Operations

What `ironfix-fixp` implements of the FIX Performance Session Layer, what is
tested, and what is not implemented. Every "implemented" row below names the
tests that exercise it; anything not listed as implemented is not.

## Specification and schema

- **Specification:** FIX Performance Session Layer Technical Specification
  **v1.1, Draft Standard, April 18, 2019**, the latest version listed at
  <https://www.fixtrading.org/standards/fixp/> (checked 2026-10-18). v1.0 is
  the Technical Standard (approved April 15, 2021); its point-to-point
  chapter says the same as v1.1 save for wording and the WebSocket guidance
  v1.1 adds. Section numbers below refer to the v1.1 Draft Standard PDF.
- **Wire format:** the FIXP SBE message schema from
  <https://github.com/FIXTradingCommunity/fixp-specification>,
  `v1-1/resources/SBEschemaForFIXP.xml` at commit `af0e9d7e` (identical to the
  v1.0 Technical Standard's copy): `package="FIXP"`, schema id 2748, version 0,
  little-endian, 19 messages.
- **License:** the specification and schema are © FIX Protocol Ltd., licensed
  CC BY-ND 4.0. The schema is vendored verbatim in `ironfix-fixp/spec/` with
  its license and a provenance README, as the input of a conformance test, and
  is excluded from the published package. Nothing is generated from it; the
  codec is written by hand on `ironsbe-core` 0.7 (`MessageHeader`,
  `VarDataHeader`, `ReadBuffer`, `WriteBuffer`) and checked against it.

## Model

`ironfix-fixp` is a sans-IO core (ADR-0002): `FixpClient` and `FixpServer`
take decoded session messages, application-message arrivals, commands and
timer ticks, each with an explicit `Instant`, and queue `Output`s (messages
to write, a transport close, events). It reads no clock: request timestamps
are derived from a `ClockAnchor` the driver supplies. It does no framing
(`ironfix-sofh` does) and stores no application messages (the driver keeps
what it sends and replays the range `retransmit` names). It depends on
`ironfix-core` and `ironsbe-core` only.

States are an explicit enum per role. Every `match` on a state or a message
names its variants; the crate denies `clippy::wildcard_enum_match_arm`.

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
| 4 | Topic | Multicast only: a protocol violation on a point-to-point session | `test_topic_is_a_violation_and_finalization_is_unsupported` |
| 5 | Establish | Client sends it, first time and on re-establishment; server validates it, reports it and waits for `accept_establishment` / `reject_establishment` | `test_client_establish_announces_keepalive_next_seq_and_credentials`, `test_server_accept_establishment_acks_with_its_keepalive_and_next_seq` |
| 6 | EstablishmentAck | Server sends it; client matches it, checks the keepalive range, applies `NextSeqNo` | `test_client_establishment_ack_establishes`, `test_client_ignores_a_mismatched_establishment_answer` |
| 7 | EstablishmentReject | Server sends it (application decision or the automatic codes below); client reports it | `test_server_reject_establishment_keeps_the_session`, `test_client_establishment_reject_keeps_the_session_negotiated` |
| 8 | Sequence | Opens a sequenced run, heartbeat of a sequenced flow; gaps detected on it | `test_send_application_opens_with_a_sequence_then_numbers_implicitly`, `test_heartbeat_of_a_sequenced_flow_is_a_sequence` |
| 9 | Context | Accepted as a Sequence when it names this session; another session terminates | `test_context_for_this_session_acts_as_a_sequence` |
| 10 | UnsequencedHeartbeat | Heartbeat of an Unsequenced or None flow; a violation on a sequenced flow | `test_heartbeat_of_an_unsequenced_flow_is_an_unsequenced_heartbeat`, `test_unsequenced_heartbeat_on_a_sequenced_flow_is_a_violation` |
| 11 | RetransmitRequest | Sent on a Recoverable inbound gap; validated and served as the provider | see Recoverable flow |
| 12 | Retransmission | Sent per batch by the provider; validated against the request by the requester | see Recoverable flow |
| 13 | RetransmitReject | Sent for refused requests; received, abandons the requested range | see Recoverable flow |
| 14 | Terminate | Both directions; see Termination | see Termination |
| 15 | FinishedSending | **Not implemented** in the session: terminates with `UnspecifiedError` and `Event::Unsupported` | `test_topic_is_a_violation_and_finalization_is_unsupported` |
| 16 | FinishedReceiving | **Not implemented** in the session, as above | (same code path) |
| 17 | Applied | Received: numbered as an application message, reported as `Event::Applied`. Never sent by the session | `test_applied_is_reported_and_numbered` |
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
  `NextSeqNo` lower than expected on re-establishment
  (`test_server_rejects_a_next_seq_that_goes_backwards`).
- Server, automatic NegotiationReject: `DuplicateId` for a second Negotiate
  of the same session, `Unspecified` for another session
  (`test_server_rejects_a_second_negotiate`).
- Out-of-order handshake messages (a second Negotiate or Establish before the
  first is answered, a role's message sent by the other role) are violations
  (`test_server_out_of_order_handshake_messages_are_violations`,
  `test_server_treats_client_only_messages_as_violations`,
  `test_client_treats_server_only_messages_as_violations`).
- Commands in the wrong state are `FixpError::InvalidState`, with nothing sent
  (`test_server_commands_in_the_wrong_state_are_refused`).
- Handshake timeouts (`handshake_timeout`): client negotiation (closes the
  client) and establishment (back to negotiated, retry allowed, Appendix A
  7.1.12.9); server waiting for Negotiate (closes) and for the first
  Establish (closes the transport, keeps the session)
  (`test_client_negotiation_times_out`,
  `test_client_establishment_times_out_and_can_retry`,
  `test_server_handshake_timeouts`).
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
- Outbound on an Unsequenced flow: no number; on a None flow: refused
  (`test_send_application_on_an_unsequenced_flow_has_no_number`,
  `test_send_application_on_a_none_flow_is_refused`).
- Inbound: implicit numbering from the announced `NextSeqNo`; a Sequence equal
  to the expected number is a heartbeat
  (`test_inbound_messages_are_numbered_from_the_announced_next_seq`).
- Inbound violations, each answered with Terminate `UnspecifiedError`: a
  `NextSeqNo` lower than expected (Appendix A 7.3.1.2) or zero; an
  application message before any Sequence; Sequence or Context on an
  Unsequenced or None flow; an application message on a None flow
  (`test_a_lower_next_seq_terminates`, `test_a_next_seq_of_zero_terminates`,
  `test_application_message_before_any_sequence_is_a_violation`,
  `test_sequence_on_an_unsequenced_flow_is_a_violation`,
  `test_application_message_on_a_none_flow_is_a_violation`).
- Checked arithmetic: the outbound counter stops with
  `FixpError::SequenceExhausted` before reaching the `uint64` null value; an
  inbound counter that would overflow terminates
  (`test_outbound_sequence_exhaustion_is_a_typed_error`,
  `test_inbound_sequence_overflow_terminates`).

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
- A request with no retransmitted message for `retransmit_timeout` is asked
  again for what is still missing (`Event::RetransmitTimedOut`;
  `test_a_stalled_retransmission_is_requested_again`).
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
- A gap too large for NotApplied's 32-bit `Count` terminates
  (`test_a_gap_too_large_for_not_applied_terminates`).
- NotApplied received for this side's flow when it is not Idempotent
  terminates (`test_not_applied_for_a_recoverable_flow_is_a_violation`).

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
  cannot disable dead-peer detection.

## Termination (section 4.4)

Implemented and tested:

- `terminate(Finished)` waits for the counterparty's Terminate, then asks for
  the transport to close; without an answer within the keepalive interval it
  closes anyway (sections 4.4.1, 4.4.2;
  `test_graceful_terminate_waits_for_the_answer`,
  `test_terminating_gives_up_after_a_keepalive_interval`).
- Any other code closes at once (Appendix A 7.2.1;
  `test_an_error_terminate_closes_at_once`).
- A counterparty Terminate is answered with Terminate `Finished`, after which
  everything received is ignored; the responder closes the transport only if
  the initiator has not within the keepalive interval
  (`test_messages_after_a_terminate_are_ignored`).
- In-flight messages are still numbered while terminating, but nothing more is
  sent (`test_in_flight_messages_are_processed_while_terminating`).
- A Terminate naming another session is a violation
  (`test_terminate_for_another_session_is_a_violation`).
- The logical session survives every unbinding; it can be established again.

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
  nothing is copied beyond the bytes present.
- A longer block from a newer schema version is accepted and skipped
  (`test_decode_skips_a_longer_block_from_a_newer_schema_version`).
- Credentials never appear in `Debug` output or logs
  (`test_credentials_debug_never_shows_the_secret`,
  `test_client_debug_never_shows_credentials`, `tests/loopback.rs`).

## Decisions where the specification is open or inconsistent

| Topic | Specification | Decision |
|---|---|---|
| RetransmitRequest for numbers not yet sent | 4.6.2.3 and Appendix A 7.3.5: RetransmitReject `OutOfRange`; 6.3: a violation | RetransmitReject `OutOfRange`; a zero `Count` too |
| Code of the answer to a Terminate | 4.4.1 says to answer, not with which code | `Finished` |
| `NextSeqNo` lower than expected | Appendix A 7.2.2, 7.2.3, 7.3.1.2 (informative) | Terminate `UnspecifiedError`; a server refuses such an Establish with `Unspecified` instead |
| A Sequence inside a retransmission batch | 3.5.4: a context switch ends the sequence | Ends the batch; the rest is requested again if it never comes |
| When to ask again for the rest of a request | 4.6.2.2: "the requester's responsibility" | After `retransmit_timeout` without a retransmitted message |
| After a RetransmitReject | Not specified | The range is abandoned and reported |
| Leniency on the counterparty's silence | 4.4: "some leniency" | Grace equal to its interval by default (configurable) |
| Session id validity | 3.4.1: a version 4 UUID; Appendix A 7.1.7.3 refuses all zeros | Only the nil UUID is refused |
| NotApplied when this side's flow is None | Not specified | Not sent; the gap is reported as an event |
| Context `NextSeqNo` | Optional in 3.5.3, required in the schema | Required, as the schema says |
| `NextSeqNo` in Establish on an Idempotent flow | 4.3.1: "re-establishment of a recoverable flow only"; Appendix A 7.1.10 sends it | Sent on every sequenced flow, first establishment included |
| Applied range | Not specified | Reported as received, not validated |

## Not implemented

- **Finalization** (section 4.7): FinishedSending / FinishedReceiving
  encode and decode, but the handshake is not run; receiving either
  terminates the binding, and a logical session is never finalized.
- **Multiplexing** (section 3.5.3): one session per transport.
- **Datagram transports** (section 3.5.2): a stream is assumed; no Sequence at
  the start of each datagram.
- **Multicast** (section 5), **WebSocket** (section 4.9), and applying
  in-band templates (section 3.6).
- **Session-layer persistence**: sequence numbers and gaps live in memory; a
  restarted process cannot re-establish a session.
- **Application-message storage**: the driver's job.
- **Engine integration**: no driver; FIXP over SOFH in `ironfix-engine` behind
  a `fixp` feature is issue #96, and a conformance suite is #97.
