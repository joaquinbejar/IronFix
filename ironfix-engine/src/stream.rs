/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The byte stream a session runs over, with its type erased.
//!
//! Both engines frame a session with [`FixCodec`](ironfix_transport::FixCodec)
//! over a byte stream they do not need to know the type of: a dialled or
//! accepted [`TcpStream`], or any stream the caller opened itself and handed to
//! [`Initiator::establish`](crate::Initiator::establish),
//! [`Acceptor::serve_stream`](crate::Acceptor::serve_stream) or
//! [`AcceptorRegistry::serve_stream`](crate::AcceptorRegistry::serve_stream)
//! (a TLS stream, a Unix socket, a proxied connection, an in-memory
//! [`tokio::io::duplex`] pipe). The public entry points take any
//! `S: AsyncRead + AsyncWrite + Unpin + Send + 'static`; this module boxes it
//! into one [`BoxedStream`] at the entry point, and the handshakes and the
//! reactor run over `Framed<BoxedStream, FixCodec>` from there on.
//!
//! # Why a box rather than a type parameter
//!
//! A type parameter would ripple through every type the session touches: the
//! reactor and its task, the handshake helpers, `SessionParams`, the
//! `AcceptorRegistry` routing path, and, to be nameable by a caller,
//! [`Connection`](crate::Connection) and the engines themselves, which would
//! then have to be told the stream type up front or be monomorphised once per
//! stream type. Boxing keeps all of that unchanged: no public type gains a
//! parameter, and the registry can route connections arriving over different
//! stream types to the same sessions.
//!
//! The cost is stated rather than measured. The stream is moved into one heap
//! allocation when the session starts, and every poll of it (each read the
//! codec's buffer refill makes, each write and flush of an outbound frame) is
//! a call through a vtable rather than a direct call. That is per poll of the
//! transport, not per field or per byte, and over a socket each such poll is
//! normally a system call. No benchmark has measured it: the workspace has no
//! engine-level harness, so no figure is claimed either way.
//!
//! `Unpin` is required by the public bound although the pinned box does not
//! need it. Every stream Tokio and its ecosystem hand out (TCP and Unix
//! sockets, TLS streams, duplex pipes) is `Unpin`, the bound matches the one a
//! non-boxed `Framed` would need, and dropping it later is not a breaking
//! change, whereas adding it would be.
//!
//! # TCP
//!
//! The TCP entry points ([`Initiator::connect`](crate::Initiator::connect),
//! [`Acceptor::serve`](crate::Acceptor::serve) and
//! [`Acceptor::accept`](crate::Acceptor::accept), and the registry's) go
//! through [`tcp`], which sets `TCP_NODELAY` before boxing, as they always
//! have. A caller-provided stream is used as it is: the engine cannot reach a
//! socket option through an arbitrary stream, so setting it is the caller's.

use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// What a session's byte stream must be once erased: readable, writable, and
/// movable to the reactor task.
///
/// Implemented for every type that qualifies, so it is never implemented by
/// hand. `Unpin` is not part of it: the box is pinned, so the erased stream
/// need not be.
pub(crate) trait AsyncReadWrite: AsyncRead + AsyncWrite + Send {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Send + ?Sized {}

/// The type-erased byte stream every session is framed over.
pub(crate) type BoxedStream = Pin<Box<dyn AsyncReadWrite>>;

/// Erases a caller-provided stream, unchanged.
#[must_use]
pub(crate) fn boxed<S>(stream: S) -> BoxedStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Box::pin(stream)
}

/// Erases a dialled or accepted TCP stream, after setting `TCP_NODELAY` on it.
///
/// FIX messages are small and latency-sensitive, so Nagle's algorithm is
/// turned off on every TCP session, as the engines always have. A failure to
/// set the option is ignored, as it always was: the session still works, only
/// with Nagle's delay.
#[must_use]
pub(crate) fn tcp(stream: TcpStream) -> BoxedStream {
    boxed(with_nodelay(stream))
}

/// Sets `TCP_NODELAY` on `stream` and hands it back.
#[must_use]
fn with_nodelay(stream: TcpStream) -> TcpStream {
    let _ = stream.set_nodelay(true);
    stream
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

    /// `TCP_NODELAY` is what every TCP entry point sets before it boxes the
    /// stream ([`tcp`] is the only way a `TcpStream` reaches a session). The
    /// option is local to a socket the engine owns and never exposes once the
    /// handshake starts, so it is checked here, on the stream [`tcp`] boxes,
    /// rather than from the peer's end, which cannot see it.
    #[tokio::test]
    async fn test_with_nodelay_tcp_stream_sets_nodelay() {
        let (dialled, accepted) = loopback_pair().await;
        for stream in [dialled, accepted] {
            ok(stream.set_nodelay(false), "clear TCP_NODELAY");
            assert!(!ok(stream.nodelay(), "read TCP_NODELAY"));
            let stream = with_nodelay(stream);
            assert!(
                ok(stream.nodelay(), "read TCP_NODELAY"),
                "a TCP session runs with Nagle's algorithm off"
            );
        }
    }

    /// The boxed stream carries bytes both ways unchanged, for TCP and for a
    /// caller-provided stream alike.
    #[tokio::test]
    async fn test_boxed_streams_carry_bytes_both_ways() {
        let (dialled, accepted) = loopback_pair().await;
        let (left, right) = tokio::io::duplex(64);
        for (mut near, mut far) in [(tcp(dialled), tcp(accepted)), (boxed(left), boxed(right))] {
            ok(near.write_all(b"8=FIX.4.4").await, "write near");
            ok(near.flush().await, "flush near");
            let mut buf = [0_u8; 9];
            ok(far.read_exact(&mut buf).await, "read far");
            assert_eq!(&buf, b"8=FIX.4.4");

            ok(far.write_all(b"10=000").await, "write far");
            ok(far.flush().await, "flush far");
            let mut buf = [0_u8; 6];
            ok(near.read_exact(&mut buf).await, "read near");
            assert_eq!(&buf, b"10=000");
        }
    }
}
