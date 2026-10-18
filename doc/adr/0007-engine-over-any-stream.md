# ADR-0007 — The engines over any AsyncRead + AsyncWrite stream

- **Status:** Accepted (issue #63, in the plan the owner approved; the
  erasure revised in the #63 performance review)
- **Date:** 2026-10-18

## Context

Both engines were hard-wired to `tokio::net::TcpStream`: the reactor framed a
`Framed<TcpStream, FixCodec>`, `Acceptor::serve` and `AcceptorRegistry::serve`
took a `TcpStream`, and `Initiator::connect` dialled TCP itself. Gateways need
FIX over TLS with a TLS stack and crypto provider the integrator chooses;
others need Unix sockets or proxied connections, and tests need an in-memory
transport. `FixCodec` already works over any stream, so the seam belongs in
`ironfix-engine`.

Constraints any answer keeps:

- no new dependency, and `ironfix-transport` unchanged;
- no typestate, sequence, heartbeat or store change, and the acceptor's check
  order and refusal groups (ADR-0017), the registry's routing (ADR-0018) and
  `NextExpectedMsgSeqNum` (789, ADR-0021) unchanged on every path;
- the existing TCP entry points keep their signatures and their behaviour,
  `TCP_NODELAY` included;
- no public type gains a stream type parameter;
- the public surface change is additive.

## Options

1. **A type parameter `S`** on the reactor, the handshake helpers and
   `SessionParams`. It ripples into every type the session touches; either the
   engines and `Connection` carry `S`, so a caller names the stream type up
   front, or the reactor is monomorphised once per stream type. A registry
   could no longer route connections of different stream types to the same
   sessions.
2. **Box every stream** behind one `Pin<Box<dyn ...>>`. This was the first
   cut. The performance review read the generated code (fat LTO, aarch64, the
   `fix44_engine_client` example) and found that TCP sessions then paid three
   indirect calls per outbound frame where they paid none, two of which had
   compiled away; an indirect call on every read poll, including the `Pending`
   poll on each wakeup; an extra allocation per session; and a tokio-util
   pointer assertion in `poll_read_buf` that was no longer optimised out.
3. **A private enum with a TCP fast path** (chosen).

## Decision

### The public API

Three methods, additive:

```rust
impl<A: Application + 'static> Initiator<A> {
    pub async fn establish<S>(&self, stream: S) -> Result<Connection, EngineError>
    where S: AsyncRead + AsyncWrite + Unpin + Send + 'static;
}
impl<A: Application + 'static> Acceptor<A> {
    pub async fn serve_stream<S>(&self, stream: S) -> Result<Connection, EngineError>;
}
impl<A: Application + 'static> AcceptorRegistry<A> {
    pub async fn serve_stream<S>(&self, stream: S) -> Result<Connection, EngineError>;
}
```

with the same bound on all three. `Initiator::connect`, `Acceptor::serve` /
`accept` and `AcceptorRegistry::serve` / `accept` keep their signatures and
hand off to the same private path after the TCP dial or accept. The names
`establish` and `serve_stream` become permanent once published: renaming one
is a breaking change.

### The erasure: a private `SessionStream`

`ironfix-engine/src/stream.rs` defines `SessionStream`, a struct around a
private enum:

```rust
pub(crate) struct SessionStream(Inner);
enum Inner {
    Tcp(TcpStream),
    Erased(Pin<Box<dyn AsyncReadWrite>>), // AsyncRead + AsyncWrite + Send
}
```

It implements `AsyncRead` and `AsyncWrite` by matching on the variant, with
`#[inline]` on every method and `is_write_vectored` / `poll_write_vectored`
forwarded per variant. The handshakes and the reactor run over
`Framed<SessionStream, FixCodec>`. The TCP variant holds the socket by value;
only the stream entry points pay the box and the vtable. No public type gains
a parameter, and one registry routes connections of different stream types.

### `TCP_NODELAY`

`SessionStream::tcp` is the only way to build the TCP variant (the enum sits
behind a private field), and it sets `TCP_NODELAY`, ignoring a failure as the
engines always have. The option is therefore set on the TCP entry points, and
only there: a caller's stream is used as given, since no socket option can be
reached through an arbitrary stream, and setting one on a socket under it is
the caller's. A TCP session cannot lose the option by being built another way.

### The bound is frozen

`AsyncRead + AsyncWrite + Unpin + Send + 'static`, with no `Sync`. Once
published it can only be loosened: dropping `Unpin` (the pinned box does not
need it) would not break a caller, while adding anything (`Sync`, or a trait
through which the engine reads peer information) would. `Unpin` is kept
because every stream Tokio and its ecosystem hand out is `Unpin` and a
non-boxed `Framed` would need it; `Sync` is left out because nothing holds a
shared reference to the stream across an `.await`, and requiring it would
exclude streams for no reason.

Consequently #81's peer certificate chain cannot arrive as a bound on `S`. It
needs a new entry point or an extra argument (#81 plans a `PeerInfo`; nothing
of it is built here).

### Timeouts

The logon timeout and the write timeout apply to a caller's stream exactly as
to TCP, from the moment an entry point is called. A TLS handshake, a proxy
`CONNECT` or anything else the caller runs on the stream before handing it
over is outside both and is the caller's to bound. #81 carries an acceptance
criterion on this.

### What a caller's stream must do

It must be a well-behaved `AsyncRead`: `poll_read` fills the `ReadBuf` it is
handed and never swaps it for another one. tokio-util's `poll_read_buf`
asserts this, so a stream that breaks it panics the task reading it, and under
`panic = "abort"` (this workspace's release profile) the process. The caller
should also pass the stream's concrete type: a stream that is already boxed
is boxed again, for two allocations and two vtable hops on every call.

## Consequences

- **Cost, stated and not measured.** The TCP path is unaffected by the seam:
  no allocation and no dynamic call, only the match on the variant. A
  caller's stream costs one allocation per session; each outbound frame
  written in one piece costs three dynamic calls (`is_write_vectored`,
  `poll_write_vectored`, `poll_flush`), and each read poll one, the `Pending`
  poll on each wakeup included. The workspace has no engine-level benchmark,
  so no figure is claimed either way.
- The handshake rules hold unchanged on the new paths; the entry points differ
  only in how the `SessionStream` is built.
- Tests: `ironfix-engine/tests/stream_tests.rs` runs both roles and a
  registry over `tokio::io::duplex` (and a caller-defined stream type), with
  no socket, through Logon, application messages, a `ResendRequest` answered
  from the store, and Logout, plus the timeout, authentication, store and
  mid-handshake close paths. `TCP_NODELAY` is checked on the real socket after
  a handshake through `Acceptor::serve` and `AcceptorRegistry::serve`, via a
  second handle on it, and on `SessionStream::tcp` by a unit test; the
  initiator's dialled socket is never exposed, so `Initiator::connect` is
  covered by the constructor test alone.
- Not done: TLS itself and `PeerInfo` (#81); a peer address for caller
  streams (no TCP path uses one today, so nothing was made optional).
- Semver: three new methods on public types, a minor change.
