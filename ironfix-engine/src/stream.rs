/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The byte stream a session runs over: a TCP socket held by value, or any
//! other stream, erased.
//!
//! Both engines frame a session with [`FixCodec`](ironfix_transport::FixCodec)
//! over a [`SessionStream`], so the handshakes and the reactor run over
//! `Framed<SessionStream, FixCodec>` whatever the transport is, and no public
//! type gains a stream type parameter. The decision and its consequences are
//! recorded in ADR-0007 (`doc/adr/0007-engine-over-any-stream.md`).
//!
//! - **TCP** ([`SessionStream::tcp`], used by
//!   [`Initiator::connect`](crate::Initiator::connect),
//!   [`Acceptor::serve`](crate::Acceptor::serve) and
//!   [`AcceptorRegistry::serve`](crate::AcceptorRegistry::serve), and so by
//!   their `accept`): the socket is held by value and `TCP_NODELAY` is set on
//!   it. Every poll is a direct call after a match on the variant; there is
//!   no allocation and no dynamic call.
//! - **Any other stream** ([`SessionStream::erased`], used by
//!   [`Initiator::establish`](crate::Initiator::establish),
//!   [`Acceptor::serve_stream`](crate::Acceptor::serve_stream) and
//!   [`AcceptorRegistry::serve_stream`](crate::AcceptorRegistry::serve_stream)):
//!   the stream is moved into one heap allocation, and every poll is a call
//!   through its vtable. An outbound frame written in one piece costs three
//!   dynamic calls (`is_write_vectored`, `poll_write_vectored`, `poll_flush`),
//!   and every read poll costs one, the `Pending` poll on each wakeup
//!   included. Nothing has measured what that costs.
//!
//! The TCP variant cannot be built except through [`SessionStream::tcp`], so a
//! TCP session cannot lose `TCP_NODELAY` by being built another way.

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// What an erased stream must be: readable, writable, and movable to the
/// reactor task.
///
/// Implemented for every type that qualifies, so it is never implemented by
/// hand. `Unpin` is not part of it: the box is pinned, so the erased stream
/// need not be.
pub(crate) trait AsyncReadWrite: AsyncRead + AsyncWrite + Send {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Send + ?Sized {}

/// The byte stream every session is framed over.
///
/// A struct around a private enum, so that the TCP variant is built only by
/// [`SessionStream::tcp`], which sets `TCP_NODELAY`.
pub(crate) struct SessionStream(Inner);

/// Which kind of stream a [`SessionStream`] holds.
enum Inner {
    /// A dialled or accepted TCP socket, with `TCP_NODELAY` set.
    Tcp(TcpStream),
    /// Any other stream, boxed once.
    Erased(Pin<Box<dyn AsyncReadWrite>>),
}

impl std::fmt::Debug for SessionStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Inner::Tcp(stream) => f.debug_tuple("Tcp").field(stream).finish(),
            Inner::Erased(_) => f.write_str("Erased"),
        }
    }
}

impl SessionStream {
    /// A dialled or accepted TCP socket, held by value, after setting
    /// `TCP_NODELAY` on it.
    ///
    /// FIX messages are small and latency-sensitive, so Nagle's algorithm is
    /// turned off on every TCP session, as the engines always have. A failure
    /// to set the option is ignored, as it always was: the session still
    /// works, only with Nagle's delay.
    #[must_use]
    pub(crate) fn tcp(stream: TcpStream) -> Self {
        let _ = stream.set_nodelay(true);
        Self(Inner::Tcp(stream))
    }

    /// Any stream a caller provided, boxed once and otherwise used as it is:
    /// no socket option can be reached through it.
    #[must_use]
    pub(crate) fn erased<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self(Inner::Erased(Box::pin(stream)))
    }
}

impl AsyncRead for SessionStream {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            Inner::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Inner::Erased(stream) => stream.as_mut().poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SessionStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().0 {
            Inner::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Inner::Erased(stream) => stream.as_mut().poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().0 {
            Inner::Tcp(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Inner::Erased(stream) => stream.as_mut().poll_write_vectored(cx, bufs),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        match &self.0 {
            Inner::Tcp(stream) => stream.is_write_vectored(),
            Inner::Erased(stream) => stream.is_write_vectored(),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            Inner::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Inner::Erased(stream) => stream.as_mut().poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            Inner::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Inner::Erased(stream) => stream.as_mut().poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Fails the test with context instead of `.unwrap()` / `.expect()`.
    #[track_caller]
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{what}: {err:?}"),
        }
    }

    /// A connected loopback pair: (dialled, accepted).
    async fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind loopback");
        let addr = ok(listener.local_addr(), "listener address");
        let (dialled, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (
            ok(dialled, "dial loopback"),
            ok(accepted, "accept loopback").0,
        )
    }

    /// [`SessionStream::tcp`] sets `TCP_NODELAY` and keeps the socket by
    /// value. The integration tests check the option again through the
    /// acceptor entry points, after a real handshake.
    #[tokio::test]
    async fn test_session_stream_tcp_sets_nodelay_and_holds_the_socket() {
        let (dialled, accepted) = loopback_pair().await;
        for stream in [dialled, accepted] {
            ok(stream.set_nodelay(false), "clear TCP_NODELAY");
            assert!(!ok(stream.nodelay(), "read TCP_NODELAY"));
            let session = SessionStream::tcp(stream);
            let Inner::Tcp(stream) = &session.0 else {
                panic!("a TCP socket is held by value, not erased")
            };
            assert!(
                ok(stream.nodelay(), "read TCP_NODELAY"),
                "a TCP session runs with Nagle's algorithm off"
            );
            assert!(
                session.is_write_vectored(),
                "TCP's vectored writes are kept"
            );
        }
    }

    /// Both variants carry bytes both ways unchanged, and the erased one
    /// reports the vectored-write support of the stream it holds.
    #[tokio::test]
    async fn test_session_streams_carry_bytes_both_ways() {
        let (dialled, accepted) = loopback_pair().await;
        let (left, right) = tokio::io::duplex(64);
        let pairs = [
            (SessionStream::tcp(dialled), SessionStream::tcp(accepted)),
            (SessionStream::erased(left), SessionStream::erased(right)),
        ];
        for (mut near, mut far) in pairs {
            ok(near.write_all(b"8=FIX.4.4").await, "write near");
            ok(near.flush().await, "flush near");
            let mut buf = [0_u8; 9];
            ok(far.read_exact(&mut buf).await, "read far");
            assert_eq!(&buf, b"8=FIX.4.4");

            let parts = [IoSlice::new(b"10="), IoSlice::new(b"000")];
            let written = ok(far.write_vectored(&parts).await, "vectored write far");
            ok(far.flush().await, "flush far");
            let mut buf = vec![0_u8; written];
            ok(near.read_exact(&mut buf).await, "read near");
            assert!(b"10=000".starts_with(&buf), "{buf:?}");
        }
        let (left, _right) = tokio::io::duplex(64);
        assert_eq!(
            SessionStream::erased(left).is_write_vectored(),
            tokio::io::duplex(64).0.is_write_vectored(),
            "the erased stream forwards is_write_vectored"
        );
    }
}
