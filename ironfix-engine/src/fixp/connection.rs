/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! The handle to a running FIXP session.

use crate::fixp::error::FixpEngineError;
use bytes::Bytes;
use ironfix_core::SeqNum;
use ironfix_fixp::SessionId;
use ironfix_sofh::EncodingType;
use tokio::sync::{mpsc, oneshot, watch};

/// A command for the driver task.
#[derive(Debug)]
pub(crate) enum Command {
    /// Send an application message.
    Send {
        encoding_type: EncodingType,
        payload: Bytes,
        reply: oneshot::Sender<Result<Option<SeqNum>, FixpEngineError>>,
    },
    /// Unbind with Terminate `Finished`.
    Terminate {
        reason: String,
        reply: oneshot::Sender<Result<(), FixpEngineError>>,
    },
}

/// A cheap-to-clone handle to an established FIXP session.
///
/// The session runs in a driver task that owns the transport; this handle
/// sends it commands. The task ends when the transport closes, whether this
/// handle exists or not; dropping every handle does not end it (the
/// counterparty or [`terminate`](Self::terminate) does).
#[derive(Debug, Clone)]
pub struct FixpConnection {
    session_id: SessionId,
    commands: mpsc::Sender<Command>,
    closed: watch::Receiver<bool>,
}

impl FixpConnection {
    pub(crate) const fn new(
        session_id: SessionId,
        commands: mpsc::Sender<Command>,
        closed: watch::Receiver<bool>,
    ) -> Self {
        Self {
            session_id,
            commands,
            closed,
        }
    }

    /// The same handle, naming `session_id`.
    pub(crate) fn with_session_id(&self, session_id: SessionId) -> Self {
        Self {
            session_id,
            commands: self.commands.clone(),
            closed: self.closed.clone(),
        }
    }

    /// The session identifier.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Sends an application message framed as SBE 1.0 little-endian
    /// (`EncodingType::SbeV1LittleEndian`), the encoding of the FIXP schema.
    ///
    /// Returns its sequence number on a sequenced flow (FIXP v1.1 section
    /// 3.5.1), `None` on an Unsequenced one. On a Recoverable flow the
    /// driver keeps the message to answer a RetransmitRequest
    /// (section 4.6.2).
    ///
    /// # Errors
    /// See [`send_with_encoding`](Self::send_with_encoding).
    pub async fn send(&self, payload: impl Into<Bytes>) -> Result<Option<SeqNum>, FixpEngineError> {
        self.send_with_encoding(EncodingType::SbeV1LittleEndian, payload)
            .await
    }

    /// Sends an application message framed with `encoding_type`.
    ///
    /// # Errors
    /// [`FixpEngineError::ReservedSchema`] for a payload that names the FIXP
    /// session schema, [`FixpEngineError::PayloadTooLarge`] above the frame
    /// ceiling (neither spends a sequence number),
    /// [`FixpEngineError::Session`] when the session refuses to send (not
    /// established, a None flow, sequence numbers exhausted, after
    /// FinishedReceiving), and [`FixpEngineError::Closed`] once the
    /// connection is closed.
    pub async fn send_with_encoding(
        &self,
        encoding_type: EncodingType,
        payload: impl Into<Bytes>,
    ) -> Result<Option<SeqNum>, FixpEngineError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Send {
                encoding_type,
                payload: payload.into(),
                reply,
            })
            .await
            .map_err(|_| FixpEngineError::Closed)?;
        answer.await.map_err(|_| FixpEngineError::Closed)?
    }

    /// Unbinds the session with Terminate `Finished` (FIXP v1.1 section
    /// 4.4.1). The session waits for the counterparty's Terminate, up to a
    /// keepalive interval, then closes the transport; use
    /// [`wait_closed`](Self::wait_closed) to wait for that.
    ///
    /// # Errors
    /// [`FixpEngineError::Session`] when the session is not established or
    /// the reason is too long, and [`FixpEngineError::Closed`] once closed.
    pub async fn terminate(&self, reason: impl Into<String>) -> Result<(), FixpEngineError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Terminate {
                reason: reason.into(),
                reply,
            })
            .await
            .map_err(|_| FixpEngineError::Closed)?;
        answer.await.map_err(|_| FixpEngineError::Closed)?
    }

    /// Waits until the driver task has closed the transport and ended.
    pub async fn wait_closed(&self) {
        let mut closed = self.closed.clone();
        // An error means the driver dropped its sender, which it only does
        // after signalling: the session is closed either way.
        let _ = closed.wait_for(|closed| *closed).await;
    }

    /// `true` once the driver task has closed the transport.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }
}
