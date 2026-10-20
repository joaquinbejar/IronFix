/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! A poll-driven FIX 4.4 initiator with no async runtime (issue #93,
//! ADR-0002).
//!
//! [`PollSession`] drives one session from the caller's own loop: the caller
//! calls [`PollSession::poll`] with the time, and the session reads what the
//! non-blocking `std::net` socket holds, feeds each frame to the sans-IO
//! decisions of `ironfix_session::sans_io`, writes what they decide, and
//! returns. Nothing blocks and nothing spawns. The application and the store
//! are the synchronous traits, [`SyncApplication`] and [`SyncMessageStore`].
//!
//! Framing is `FixCodec`, the codec the Tokio engine uses, called through
//! its `tokio_util` `Decoder` impl, which is a plain synchronous method: the
//! codec needs no runtime.
//!
//! The protocol rules come from the core, not from this file: which inbound
//! number is in sequence, a gap, a duplicate or too low
//! ([`route_inbound`]); what a `ResendRequest` asks for
//! ([`decide_resend_request`]) and how it is answered from the store
//! ([`ResendReplay`], [`replay_field`]); what a `SequenceReset` does
//! ([`screen_sequence_reset`], [`decide_sequence_reset`]); when a gap is
//! requested ([`SessionCore::decide_gap_request`]); and what a tick does
//! ([`SessionCore::decide_tick`]); and whether a frame's header is acceptable
//! ([`header_seq_num`], [`PeerIdentity`], [`SendingTimeGuard`]). This driver
//! keeps the socket, the buffers, the encoding, the clocks, and the order of
//! the calls.
//!
//! It is an example, not a second engine: one initiator session, FIX 4.4,
//! no TLS, no throttle, no gap queue (gapped messages are discarded and
//! recovered by the resend), and a session that ends on its first protocol
//! error with a Logout. It persists through the store before each write, in
//! the order the store contract states.

#![allow(dead_code)]

use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime};

use bytes::BytesMut;
use ironfix_core::error::StoreError;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::Timestamp;
use ironfix_core::version::FixVersion;
use ironfix_engine::application::{RejectReason, SessionId};
use ironfix_engine::{OutboundField, OutboundMessage, SyncApplication};
use ironfix_session::SessionConfig;
use ironfix_session::header::{
    HeartBtIntProblem, PeerIdentity, SendingTimeGuard, check_encrypt_method, header_seq_num,
    parse_heartbeat_interval,
};
use ironfix_session::heartbeat::{HeartbeatManager, generate_test_req_id};
use ironfix_session::sans_io::{
    AckHeartBtIntDefect, EndSeqNoInfinity, EntryScreen, GapDisposition, GapRequest, InboundRoute,
    LivenessAction, LogonRole, PageRead, ReplayAction, ReplayField, ReplayStep, ReplayVerdict,
    ResendReplay, ResendRequestDecision, ResetDecision, ResetScreen, SessionCore, SessionPhase,
    TickDecision, TickInput, decide_resend_request, decide_sequence_reset, interval_change,
    negotiate_logon_interval, orig_sending_time, replay_field, route_inbound,
    screen_sequence_reset, test_request_reply_id,
};
use ironfix_session::sequence::SequenceManager;
use ironfix_session::state::{LogonSent, Session};
use ironfix_store::SyncMessageStore;
use ironfix_tagvalue::{Decoder as FrameDecoder, Encoder};
use ironfix_transport::FixCodec;
use tokio_util::codec::Decoder;

/// The `BeginString` (8) this driver speaks.
const BEGIN_STRING: &str = "FIX.4.4";

/// Bytes read from the socket per read call.
const READ_CHUNK: usize = 16 * 1024;

/// Why a [`PollSession`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// The Logout exchange completed.
    LoggedOut,
    /// The counterparty closed the connection.
    PeerClosed,
    /// A protocol error ended the session, with a Logout when one could be
    /// written.
    Protocol(String),
    /// The socket failed.
    Io(String),
}

/// Where a [`PollSession`] is.
#[derive(Debug)]
enum Stage {
    /// Our Logon is out; the acknowledgement is awaited.
    LogonSent(Session<LogonSent>),
    /// Established, the phase held by the core.
    Live,
    /// Ended.
    Ended(Ended),
}

/// One FIX 4.4 initiator session driven by the caller's loop.
pub struct PollSession<A: SyncApplication, S: SyncMessageStore> {
    stream: TcpStream,
    codec: FixCodec,
    read_buf: BytesMut,
    out: Vec<u8>,
    config: SessionConfig,
    session_id: SessionId,
    sequences: SequenceManager,
    heartbeat: HeartbeatManager,
    core: SessionCore<()>,
    identity: PeerIdentity,
    sending_time: SendingTimeGuard,
    stage: Stage,
    app: A,
    store: S,
}

impl<A: SyncApplication, S: SyncMessageStore> PollSession<A, S> {
    /// Connects to `addr`, switches the socket to non-blocking, and queues
    /// the Logon at the store's next sender number. The first
    /// [`PollSession::poll`] writes it.
    ///
    /// # Errors
    /// The connect or the socket setup failed.
    pub fn connect(
        addr: SocketAddr,
        config: SessionConfig,
        app: A,
        store: S,
        now: Instant,
    ) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        stream.set_nodelay(true)?;
        stream.set_nonblocking(true)?;
        let session_id = SessionId::new(
            BEGIN_STRING,
            config.sender_comp_id.as_str(),
            config.target_comp_id.as_str(),
        );
        let sequences = SequenceManager::new();
        sequences.set_sender_seq(store.next_sender_seq());
        sequences.set_target_seq(store.next_target_seq());
        let heartbeat = HeartbeatManager::new(config.heartbeat_interval, now);
        let identity = PeerIdentity::new(&config);
        let sending_time = SendingTimeGuard::new(&config);
        let session = Session::new(session_id.to_string())
            .connect()
            .send_logon(now);
        let mut this = Self {
            stream,
            codec: FixCodec::new(),
            read_buf: BytesMut::with_capacity(READ_CHUNK),
            out: Vec::with_capacity(READ_CHUNK),
            config,
            session_id,
            sequences,
            heartbeat,
            core: SessionCore::new(),
            identity,
            sending_time,
            stage: Stage::LogonSent(session),
            app,
            store,
        };
        this.app.on_create(&this.session_id);
        let mut logon = OutboundMessage::new(MsgType::Logon);
        logon.push_str(98, "0");
        let interval = this.config.heartbeat_interval.as_secs();
        logon.push_uint(108, interval);
        if let Err(reason) = this.send_admin(logon, now) {
            return Err(io::Error::other(reason));
        }
        Ok(this)
    }

    /// The session's identity.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// The application.
    pub const fn app(&self) -> &A {
        &self.app
    }

    /// The store.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Whether the Logon exchange is done and the session is established
    /// with no Logout of its own sent.
    pub const fn is_active(&self) -> bool {
        matches!(self.stage, Stage::Live) && self.core.is_active()
    }

    /// Why the session ended, once it has.
    pub const fn ended(&self) -> Option<&Ended> {
        match &self.stage {
            Stage::Ended(ended) => Some(ended),
            Stage::LogonSent(_) | Stage::Live => None,
        }
    }

    /// One pass of the caller's loop at `now`: writes what is waiting, reads
    /// and handles every complete inbound frame, then runs the periodic
    /// tick. Returns whether anything was read or written, so a caller can
    /// back off when idle.
    pub fn poll(&mut self, now: Instant) -> bool {
        if self.ended().is_some() {
            return false;
        }
        let mut progressed = self.flush(now);
        let (read, eof) = self.read();
        progressed |= read;
        // Frames read before the counterparty closed are handled first: its
        // Logout often arrives with the close.
        while self.ended().is_none() {
            match self.codec.decode(&mut self.read_buf) {
                Ok(Some(frame)) => self.on_frame(&frame, now),
                Ok(None) => break,
                Err(err) => {
                    self.fail(format!("inbound framing failed: {err}"), now);
                    break;
                }
            }
        }
        if eof {
            self.end(Ended::PeerClosed);
        }
        if matches!(self.stage, Stage::Live) {
            self.on_tick(now);
        }
        progressed |= self.flush(now);
        progressed
    }

    /// Sends an application message through the outbound gate
    /// ([`SyncApplication::to_app_checked`]): it is numbered, filed, and
    /// written by the next [`PollSession::poll`]. Returns its `MsgSeqNum`.
    ///
    /// # Errors
    /// The session is not active, the gate vetoed the message, or the store
    /// refused it.
    pub fn send_app(&mut self, mut message: OutboundMessage, now: Instant) -> Result<u64, String> {
        if !self.is_active() {
            return Err("the session is not active".to_string());
        }
        self.app
            .to_app_checked(&mut message, &self.session_id)
            .map_err(|reason| format!("vetoed: {}", reason.text))?;
        self.frame_and_queue(&message, now)
    }

    /// Starts this session's Logout. The session ends once the counterparty
    /// answers, or the logout timeout runs out.
    pub fn logout(&mut self, now: Instant) {
        if !self.is_active() {
            return;
        }
        let logout = OutboundMessage::new(MsgType::Logout);
        if self.send_admin(logout, now).is_err() {
            return;
        }
        // Typestate: Active -> LogoutPending, as the Logout is queued; this
        // driver writes it on the same poll.
        if let Some(SessionPhase::Active(session)) = self.core.take_phase() {
            self.core
                .enter_phase(SessionPhase::LogoutPending(session.initiate_logout(now)));
        }
    }

    // --- Inbound ----------------------------------------------------------

    /// Reads what the socket holds now. Returns whether anything was read,
    /// and whether the counterparty closed its side.
    fn read(&mut self) -> (bool, bool) {
        let mut chunk = [0_u8; READ_CHUNK];
        let mut progressed = false;
        loop {
            match self.stream.read(&mut chunk) {
                Ok(0) => return (progressed, true),
                Ok(read) => {
                    self.read_buf.extend_from_slice(&chunk[..read]);
                    progressed = true;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => return (progressed, false),
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Err(err) => {
                    self.end(Ended::Io(err.to_string()));
                    return (progressed, false);
                }
            }
        }
    }

    /// Handles one complete inbound frame.
    fn on_frame(&mut self, frame: &[u8], now: Instant) {
        let mut decoder = FrameDecoder::new(frame);
        let raw = match decoder.decode() {
            Ok(raw) => raw,
            Err(err) => return self.fail(format!("inbound frame does not decode: {err}"), now),
        };
        // The header checks of the core, in the Tokio driver's order:
        // MsgSeqNum (34) in the standard header, the counterparty's
        // identity, then SendingTime (52), all before the message counts as
        // proof of life.
        let msg_type = raw.msg_type().clone();
        let Some(seq) = header_seq_num(&raw) else {
            return self.fail("inbound message without MsgSeqNum (34)".to_string(), now);
        };
        if let Err(mismatch) = self.identity.validate(&raw) {
            return self.fail(mismatch.to_string(), now);
        }
        if let Err(problem) = self
            .sending_time
            .validate(&raw, Timestamp::now().as_millis())
        {
            return self.fail(problem.to_string(), now);
        }
        let _ = self.heartbeat.on_message_received(
            msg_type == MsgType::Heartbeat,
            raw.get_field_str(112),
            now,
        );
        if let Stage::LogonSent(_) = self.stage {
            return self.on_logon_ack(&raw, &msg_type, seq, now);
        }
        match route_inbound(&self.sequences, &msg_type, seq, || {
            raw.get_field_str(43) == Some("Y")
        }) {
            InboundRoute::SequenceReset => self.on_sequence_reset(&raw, seq, now),
            InboundRoute::Admin { next } => {
                if !self.consume(next, now) {
                    return;
                }
                self.on_admin(&raw, &msg_type, now);
            }
            InboundRoute::App => {
                let Some(next) = seq.checked_add(1) else {
                    return self.fail("inbound MsgSeqNum exhausted".to_string(), now);
                };
                if !self.consume(next, now) {
                    return;
                }
                if let Err(reason) = self.app.from_app(&raw, &self.session_id) {
                    self.reject(seq, &msg_type, &reason, now);
                }
            }
            InboundRoute::Exhausted => self.fail("inbound MsgSeqNum exhausted".to_string(), now),
            InboundRoute::Duplicate => {}
            InboundRoute::TooLow { expected, received } => self.fail(
                format!("MsgSeqNum too low, expecting {expected} but received {received}"),
                now,
            ),
            InboundRoute::Gap {
                expected,
                received,
                then,
            } => {
                self.request_gap(expected, received, now);
                match then {
                    // No gap queue here: an application message is recovered
                    // by the resend.
                    GapDisposition::QueueFrame => {}
                    // An admin message is acted on now, without advancing
                    // the expectation: a TestRequest above a gap still gets
                    // its Heartbeat, a ResendRequest its answer.
                    GapDisposition::KeepNumber | GapDisposition::Dispatch => {
                        self.on_admin(&raw, &msg_type, now);
                    }
                }
            }
        }
    }

    /// The counterparty's Logon acknowledgement.
    fn on_logon_ack(&mut self, raw: &RawMessage<'_>, msg_type: &MsgType, seq: u64, now: Instant) {
        if *msg_type != MsgType::Logon {
            return self.fail(
                format!("expected a Logon acknowledgement, got {msg_type}"),
                now,
            );
        }
        if let Err(reason) = self.app.from_admin(raw, &self.session_id) {
            return self.fail(
                format!("Logon acknowledgement refused: {}", reason.text),
                now,
            );
        }
        // EncryptMethod (98) is required, and only 0 (None) is supported: a
        // session Reject (RefTagID 98) and a Logout otherwise, as the
        // engine's initiator does.
        if let Err(problem) = check_encrypt_method(raw) {
            let detail = problem.to_string();
            let reason = RejectReason::new(problem.reject_code(), detail.clone())
                .with_ref_tag(problem.ref_tag());
            self.reject(seq, msg_type, &reason, now);
            let mut logout = OutboundMessage::new(MsgType::Logout);
            logout.push_str(58, &detail);
            let _ = self.send_admin(logout, now);
            let _ = self.flush(now);
            return self.end(Ended::Protocol(detail));
        }
        // HeartBtInt (108) is required on the acknowledgement, bounded, and
        // adopted, as the engine's initiator does: a session Reject
        // (RefTagID 108) and a Logout otherwise.
        let negotiated = match parse_heartbeat_interval(raw) {
            Ok(secs) => {
                negotiate_logon_interval(LogonRole::Initiator, self.config.heartbeat_interval, secs)
                    .map_err(|err| (AckHeartBtIntDefect::OutOfRange, err.to_string()))
            }
            Err(problem @ HeartBtIntProblem::Missing) => {
                Err((AckHeartBtIntDefect::Missing, problem.to_string()))
            }
            Err(problem @ HeartBtIntProblem::Malformed { .. }) => {
                Err((AckHeartBtIntDefect::Malformed, problem.to_string()))
            }
            Err(problem @ HeartBtIntProblem::OutOfRange { .. }) => {
                Err((AckHeartBtIntDefect::OutOfRange, problem.to_string()))
            }
        };
        let negotiated = match negotiated {
            Ok(interval) => interval,
            Err((defect, detail)) => {
                let reason = RejectReason::new(defect.session_reject_reason(), detail.clone())
                    .with_ref_tag(108);
                self.reject(seq, msg_type, &reason, now);
                let mut logout = OutboundMessage::new(MsgType::Logout);
                logout.push_str(58, &detail);
                let _ = self.send_admin(logout, now);
                let _ = self.flush(now);
                return self.end(Ended::Protocol(detail));
            }
        };
        if let Some(interval) = interval_change(self.heartbeat.interval(), negotiated) {
            self.heartbeat = HeartbeatManager::new(interval, now);
        }
        let route = route_inbound(&self.sequences, msg_type, seq, || false);
        let Stage::LogonSent(session) = std::mem::replace(&mut self.stage, Stage::Live) else {
            return;
        };
        // Typestate: LogonSent -> Active.
        self.core
            .enter_phase(SessionPhase::Active(session.on_logon_ack()));
        match route {
            InboundRoute::Admin { next } => {
                if !self.consume(next, now) {
                    return;
                }
            }
            InboundRoute::Gap {
                expected, received, ..
            } => {
                // The acknowledgement is ahead of us: it is accepted, and the
                // gap below it requested once the session is up.
                self.app.on_logon(&self.session_id);
                return self.request_gap(expected, received, now);
            }
            _ => {
                return self.fail(
                    format!("Logon acknowledgement at {seq} is below the expected number"),
                    now,
                );
            }
        }
        self.app.on_logon(&self.session_id);
    }

    /// Persists `next` as the next inbound number, then consumes the
    /// number: the store contract's order. `false` once the session ended.
    fn consume(&mut self, next: u64, now: Instant) -> bool {
        if let Err(err) = self.store.set_next_target_seq(next) {
            self.fail(format!("store refused the target number: {err}"), now);
            return false;
        }
        if self.sequences.try_increment_target_seq().is_err() {
            self.fail("inbound MsgSeqNum exhausted".to_string(), now);
            return false;
        }
        let target = self.sequences.next_target_seq().value();
        let _ = self.core.note_inbound_progress(target, now);
        true
    }

    /// An admin message next in sequence, or a Logout above a gap.
    fn on_admin(&mut self, raw: &RawMessage<'_>, msg_type: &MsgType, now: Instant) {
        if let Err(reason) = self.app.from_admin(raw, &self.session_id) {
            let seq = raw
                .get_field_str(34)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            return self.reject(seq, msg_type, &reason, now);
        }
        match msg_type {
            MsgType::TestRequest => {
                let mut heartbeat = OutboundMessage::new(MsgType::Heartbeat);
                if let Some(id) = test_request_reply_id(raw.get_field_str(112)) {
                    heartbeat.push_str(112, id);
                }
                let _ = self.send_admin(heartbeat, now);
            }
            MsgType::ResendRequest => self.on_resend_request(raw, now),
            MsgType::Logout => self.on_peer_logout(now),
            _ => {}
        }
    }

    /// The counterparty's Logout: completes ours, or is answered.
    fn on_peer_logout(&mut self, now: Instant) {
        match self.core.take_phase() {
            Some(SessionPhase::LogoutPending(session)) => {
                // Typestate: LogoutPending -> Disconnected.
                let _ = session.on_logout_ack();
            }
            Some(SessionPhase::Active(session) | SessionPhase::LogoutQueued(session)) => {
                let _ = self.send_admin(OutboundMessage::new(MsgType::Logout), now);
                // Typestate: Active -> LogoutPending -> Disconnected.
                let _ = session.initiate_logout(now).on_logout_ack();
            }
            None => {}
        }
        self.end(Ended::LoggedOut);
    }

    /// A `SequenceReset` (4): screened before the application sees it,
    /// decided after.
    fn on_sequence_reset(&mut self, raw: &RawMessage<'_>, seq: u64, now: Instant) {
        let screen = screen_sequence_reset(&self.sequences, raw.get_field_str(123), seq, || {
            raw.get_field_str(43) == Some("Y")
        });
        let gap_fill = match screen {
            ResetScreen::BadGapFillFlag => {
                let reason =
                    RejectReason::new(6, "GapFillFlag (123) must be Y or N").with_ref_tag(123);
                return self.reject(seq, &MsgType::SequenceReset, &reason, now);
            }
            ResetScreen::GappedFill { expected, received } => {
                return self.request_gap(expected, received, now);
            }
            ResetScreen::DuplicateFill { .. } => return,
            ResetScreen::TooLowFill { expected, received } => {
                return self.fail(
                    format!("GapFill too low, expecting {expected} but received {received}"),
                    now,
                );
            }
            ResetScreen::Exhausted => {
                return self.fail("inbound MsgSeqNum exhausted".to_string(), now);
            }
            ResetScreen::FillInSequence { next } => {
                if let Err(err) = self.store.set_next_target_seq(next) {
                    return self.fail(format!("store refused the target number: {err}"), now);
                }
                true
            }
            ResetScreen::Reset => false,
        };
        if let Err(reason) = self.app.from_admin(raw, &self.session_id) {
            // An in-sequence fill occupies its number however it is
            // answered: the persisted target already moved past it.
            if gap_fill && !self.consume_fill(now) {
                return;
            }
            return self.reject(seq, &MsgType::SequenceReset, &reason, now);
        }
        let new_seq_no = raw.get_field_str(36).and_then(|value| value.parse().ok());
        let expected = self.sequences.next_target_seq().value();
        match decide_sequence_reset(gap_fill, seq, new_seq_no, expected) {
            ResetDecision::Apply { new_seq, .. } => {
                if let Err(err) = self.store.set_next_target_seq(new_seq) {
                    return self.fail(format!("store refused the target number: {err}"), now);
                }
                self.sequences.set_target_seq(new_seq);
                let _ = self.core.note_inbound_progress(new_seq, now);
            }
            ResetDecision::MissingNewSeqNo => {
                if gap_fill && !self.consume_fill(now) {
                    return;
                }
                let reason = RejectReason::new(1, "SequenceReset without a valid NewSeqNo (36)")
                    .with_ref_tag(36);
                self.reject(seq, &MsgType::SequenceReset, &reason, now);
            }
            ResetDecision::FillNotAdvancing { new_seq } => {
                if !self.consume_fill(now) {
                    return;
                }
                let reason = RejectReason::new(
                    5,
                    format!("GapFill NewSeqNo {new_seq} does not advance past MsgSeqNum {seq}"),
                )
                .with_ref_tag(36);
                self.reject(seq, &MsgType::SequenceReset, &reason, now);
            }
            ResetDecision::ResetBelowExpected { new_seq, expected } => {
                let reason = RejectReason::new(
                    5,
                    format!("SequenceReset NewSeqNo {new_seq} is below the expected {expected}"),
                )
                .with_ref_tag(36);
                self.reject(seq, &MsgType::SequenceReset, &reason, now);
            }
        }
    }

    /// Consumes the number of an in-sequence GapFill that is rejected: its
    /// next number is already persisted ([`ResetScreen::FillInSequence`]),
    /// so the in-memory expectation follows. `false` once the session ended.
    fn consume_fill(&mut self, now: Instant) -> bool {
        if self.sequences.try_increment_target_seq().is_err() {
            self.fail("inbound MsgSeqNum exhausted".to_string(), now);
            return false;
        }
        let target = self.sequences.next_target_seq().value();
        let _ = self.core.note_inbound_progress(target, now);
        true
    }

    /// Requests the gap from `expected` when the core says a request is due.
    fn request_gap(&mut self, expected: u64, received: u64, now: Instant) {
        if self.core.decide_gap_request(expected, received) == GapRequest::AlreadyRequested {
            return;
        }
        let mut request = OutboundMessage::new(MsgType::ResendRequest);
        request.push_uint(7, expected);
        request.push_uint(16, 0);
        if self.send_admin(request, now).is_ok() {
            self.core
                .arm_requested(expected, received, &self.config, now);
        }
    }

    /// Answers a `ResendRequest` (2) from the store.
    fn on_resend_request(&mut self, raw: &RawMessage<'_>, now: Instant) {
        let begin_seq = raw.get_field_str(7).and_then(|value| value.parse().ok());
        let end_seq = raw.get_field_str(16).and_then(|value| value.parse().ok());
        let next_sender = self.sequences.next_sender_seq().value();
        let infinity = EndSeqNoInfinity::for_version(FixVersion::Fix44);
        let (begin_seq, new_seq) =
            match decide_resend_request(begin_seq, end_seq, next_sender, infinity) {
                ResendRequestDecision::Replay { begin_seq, new_seq } => (begin_seq, new_seq),
                refused => {
                    let seq = raw
                        .get_field_str(34)
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0);
                    let reason =
                        RejectReason::new(5, format!("ResendRequest refused: {refused:?}"));
                    return self.reject(seq, &MsgType::ResendRequest, &reason, now);
                }
            };
        let Some(mut replay) = ResendReplay::new(begin_seq, new_seq, true) else {
            return;
        };
        loop {
            match replay.poll_store() {
                ReplayStep::ReadPage(page) => {
                    let messages = match self.store.get_page(page.from, page.through, page.limit) {
                        Ok(messages) => messages,
                        // A store that reports itself corrupted cannot say
                        // what was sent: gap-filling over it would tell the
                        // counterparty its filed messages never existed. The
                        // session ends, as the engine's does.
                        Err(err @ StoreError::Corrupted { .. }) => {
                            return self.fail(format!("the store is corrupted: {err}"), now);
                        }
                        // Any other failed read gap-fills the rest.
                        Err(_) => {
                            replay.on_page(PageRead::Failed);
                            continue;
                        }
                    };
                    replay.on_page(PageRead::Read {
                        len: messages.len(),
                        furthest: messages.last().map(|message| message.seq_num()),
                    });
                    for message in &messages {
                        let seq = message.seq_num();
                        if replay.screen_entry(seq, message.msg_type().is_admin())
                            == EntryScreen::Skip
                        {
                            continue;
                        }
                        let rebuilt = rebuild_replay(message.payload(), now);
                        let verdict = match &rebuilt {
                            Some(frame) => {
                                let mut decoder = FrameDecoder::new(frame);
                                match decoder.decode() {
                                    Ok(replayed) => {
                                        match self.app.to_app_resend(&replayed, &self.session_id) {
                                            Ok(()) => ReplayVerdict::Replay,
                                            Err(_) => ReplayVerdict::GapFill,
                                        }
                                    }
                                    Err(_) => ReplayVerdict::GapFill,
                                }
                            }
                            None => ReplayVerdict::GapFill,
                        };
                        match replay.decide_entry(seq, verdict) {
                            ReplayAction::Skip => {}
                            ReplayAction::Replay { .. } => self.queue_rebuilt(rebuilt.as_deref()),
                            ReplayAction::GapFillThenReplay { gap_fill, .. } => {
                                self.queue_gap_fill(gap_fill.at, gap_fill.new_seq, now);
                                self.queue_rebuilt(rebuilt.as_deref());
                            }
                        }
                    }
                }
                ReplayStep::StoreExhausted => {}
                ReplayStep::Complete { gap_fill } => {
                    if let Some(fill) = gap_fill {
                        self.queue_gap_fill(fill.at, fill.new_seq, now);
                    }
                    break;
                }
            }
        }
    }

    // --- Periodic tick ------------------------------------------------------

    /// What the core decides at `now`.
    fn on_tick(&mut self, now: Instant) {
        let Some(phase) = self.core.take_phase() else {
            return;
        };
        let decision = self.core.decide_tick(
            &phase,
            &TickInput {
                now,
                logout_timeout: self.config.logout_timeout,
                heartbeat: &self.heartbeat,
                output_waiting: !self.out.is_empty(),
                resend_request_unwritten: false,
                output_bound_reached: false,
            },
        );
        self.core.enter_phase(phase);
        match decision {
            TickDecision::LogoutTimedOut => {
                self.end(Ended::Protocol("logout timed out".to_string()))
            }
            TickDecision::ResendUnderWay => {}
            TickDecision::Stalled(_) => {
                self.fail("a sequence gap was not filled in time".to_string(), now);
            }
            TickDecision::Liveness(LivenessAction::Idle) => {}
            TickDecision::Liveness(LivenessAction::CloseHeartbeatTimeout) => {
                self.end(Ended::Protocol("heartbeat timeout".to_string()));
            }
            TickDecision::Liveness(LivenessAction::SendTestRequest) => {
                let id = generate_test_req_id(SystemTime::now());
                let mut request = OutboundMessage::new(MsgType::TestRequest);
                request.push_str(112, &id);
                if self.send_admin(request, now).is_ok() {
                    self.heartbeat.on_test_request_sent(id, now);
                }
            }
            TickDecision::Liveness(LivenessAction::SendHeartbeat) => {
                let _ = self.send_admin(OutboundMessage::new(MsgType::Heartbeat), now);
            }
        }
    }

    // --- Outbound -----------------------------------------------------------

    /// An admin message through `to_admin`, numbered, filed and queued.
    fn send_admin(&mut self, mut message: OutboundMessage, now: Instant) -> Result<u64, String> {
        self.app.to_admin(&mut message, &self.session_id);
        self.frame_and_queue(&message, now)
    }

    /// Numbers `message`, encodes it, files it with the next sender number
    /// (before the bytes are queued, as the store contract orders), and
    /// queues it.
    fn frame_and_queue(&mut self, message: &OutboundMessage, now: Instant) -> Result<u64, String> {
        let seq = self.sequences.next_sender_seq().value();
        let Some(next) = seq.checked_add(1) else {
            return Err("outbound MsgSeqNum exhausted".to_string());
        };
        let mut encoder = Encoder::new(BEGIN_STRING);
        encoder.put_str(35, message.msg_type().as_str());
        encoder.put_str(49, self.config.sender_comp_id.as_str());
        encoder.put_str(56, self.config.target_comp_id.as_str());
        encoder.put_uint(34, seq);
        encoder.put_str(52, Timestamp::now().format_millis().as_str());
        for field in message.fields() {
            match field {
                OutboundField::Raw { tag, value } => encoder.put_raw(*tag, value),
                OutboundField::Data {
                    length_tag,
                    data_tag,
                    value,
                } => encoder.put_data(*length_tag, *data_tag, value),
            }
        }
        let frame = encoder
            .finish()
            .map_err(|err| format!("encode failed: {err}"))?
            .to_vec();
        self.store
            .file_outbound(seq, message.msg_type(), &frame, next)
            .map_err(|err| format!("store refused the frame: {err}"))?;
        self.sequences.set_sender_seq(next);
        self.out.extend_from_slice(&frame);
        self.heartbeat.on_message_sent(now);
        Ok(seq)
    }

    /// Queues a rebuilt replay frame (its number is its original one).
    fn queue_rebuilt(&mut self, frame: Option<&[u8]>) {
        if let Some(frame) = frame {
            self.out.extend_from_slice(frame);
        }
    }

    /// Queues a SequenceReset-GapFill numbered `at` with `NewSeqNo` `new_seq`
    /// (it occupies numbers already spent, so it spends none).
    fn queue_gap_fill(&mut self, at: u64, new_seq: u64, now: Instant) {
        let mut encoder = Encoder::new(BEGIN_STRING);
        encoder.put_str(35, MsgType::SequenceReset.as_str());
        encoder.put_str(49, self.config.sender_comp_id.as_str());
        encoder.put_str(56, self.config.target_comp_id.as_str());
        encoder.put_uint(34, at);
        encoder.put_str(43, "Y");
        let sent = Timestamp::now().format_millis();
        encoder.put_str(52, sent.as_str());
        encoder.put_str(122, sent.as_str());
        encoder.put_str(123, "Y");
        encoder.put_uint(36, new_seq);
        if let Ok(frame) = encoder.finish() {
            self.out.extend_from_slice(frame);
            self.heartbeat.on_message_sent(now);
        }
    }

    /// A session-level Reject (3) of the message numbered `seq`.
    fn reject(&mut self, seq: u64, msg_type: &MsgType, reason: &RejectReason, now: Instant) {
        let mut reject = OutboundMessage::new(MsgType::Reject);
        reject.push_uint(45, seq);
        reject.push_str(372, msg_type.as_str());
        if let Some(tag) = reason.ref_tag {
            reject.push_uint(371, u64::from(tag));
        }
        reject.push_uint(373, u64::from(reason.code));
        reject.push_str(58, &reason.text);
        let _ = self.send_admin(reject, now);
    }

    /// Writes what is queued, as far as the socket takes it now.
    fn flush(&mut self, now: Instant) -> bool {
        let mut written = 0;
        while written < self.out.len() {
            match self.stream.write(&self.out[written..]) {
                Ok(0) => {
                    self.end(Ended::PeerClosed);
                    break;
                }
                Ok(moved) => written += moved,
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Err(err) => {
                    self.end(Ended::Io(err.to_string()));
                    break;
                }
            }
        }
        self.out.drain(..written);
        let _ = now;
        written > 0
    }

    // --- Ending -------------------------------------------------------------

    /// A protocol error: a Logout naming it, written at once if the socket
    /// takes it, then the end.
    fn fail(&mut self, text: String, now: Instant) {
        if matches!(self.stage, Stage::Live) {
            let mut logout = OutboundMessage::new(MsgType::Logout);
            logout.push_str(58, &text);
            if self.send_admin(logout, now).is_ok() {
                let _ = self.flush(now);
            }
        }
        self.end(Ended::Protocol(text));
    }

    /// Ends the session once.
    fn end(&mut self, ended: Ended) {
        if matches!(self.stage, Stage::Ended(_)) {
            return;
        }
        let was_live = matches!(self.stage, Stage::Live);
        if let Some(phase) = self.core.take_phase() {
            let _ = phase.teardown();
        }
        self.stage = Stage::Ended(ended);
        if was_live {
            self.app.on_logout(&self.session_id);
        }
    }
}

/// Rebuilds a stored frame as a replay: `PossDupFlag` (43) = Y, a fresh
/// `SendingTime` (52) and `OrigSendingTime` (122), every other field as
/// filed ([`replay_field`]). `None` if the stored frame does not decode or
/// encode.
fn rebuild_replay(stored: &[u8], _now: Instant) -> Option<Vec<u8>> {
    let mut decoder = FrameDecoder::new(stored);
    let raw = decoder.decode().ok()?;
    let sent = raw.get_field_str(52)?;
    let orig = orig_sending_time(raw.get_field_str(122), sent).to_string();
    let mut encoder = Encoder::new(BEGIN_STRING);
    // Collected so a LENGTH field can look ahead to its DATA field.
    let fields: Vec<_> = raw.fields().collect();
    let mut index = 0;
    while let Some(field) = fields.get(index) {
        index += 1;
        match replay_field(field.tag) {
            ReplayField::Framing | ReplayField::Reinserted => {}
            ReplayField::SendingTime => {
                encoder.try_put_raw(43, b"Y").ok()?;
                let now = Timestamp::now().format_millis();
                encoder.try_put_raw(52, now.as_bytes()).ok()?;
                encoder.try_put_raw(122, orig.as_bytes()).ok()?;
            }
            ReplayField::Copied if field.tag == 10 => {}
            ReplayField::Copied => {
                if encoder.try_put_raw(field.tag, field.value).is_err() {
                    // The encoder refuses a LENGTH or DATA tag on its own (it
                    // derives the count from the payload): write the pair
                    // together, as the engine's rebuild does.
                    let data = fields.get(index)?;
                    encoder.try_put_data(field.tag, data.tag, data.value).ok()?;
                    index += 1;
                }
            }
        }
    }
    encoder.finish().ok().map(<[u8]>::to_vec)
}
