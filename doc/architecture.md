# IronFix: High-Performance FIX/FAST Engine Architecture

> ## ⚠️ Status: design target, NOT an as-built description
>
> **This document describes where IronFix is going, not what it currently does.**
> Read every statement below as "the intended design", even where it is written
> in the present tense. Concretely:
>
> - **Every latency and throughput figure in this document is a target that has
>   never been measured.** A criterion harness now exists (`ironfix-tagvalue`,
>   `ironfix-fast` and `ironfix-transport` each carry a `benches/` target and
>   `make bench` runs them), but it records no baseline and ships no figures, so
>   no number here — "single-digit microseconds", "millions of messages per
>   second", "<10μs", "50-200μs" — is a benchmark result. Do not restate any of
>   them as a measurement in a README, doc comment, commit message or PR body.
> - **The module tree below does not match the repository.** It names files and
>   crates that do not exist (`ironfix/` facade crate, `transport/tcp/`,
>   `transport/tls.rs`, `transport/multicast.rs`, `store/file.rs`,
>   `store/mmap.rs`, `engine/acceptor.rs`, `fast/template.rs`,
>   `session/recovery.rs`, `dictionary/versions/`).
> - **Several "decisions" below are unbuilt.** There is no synchronous or
>   kernel-bypass mode, no arena allocator (`bumpalo` is not a dependency), no
>   compiled FAST templates, no code generation in use, no TLS, and no acceptor.
> - **Code blocks are illustrative sketches, not extracts from the codebase.**
>   Most do not compile against the current crates.
>
> For what actually exists today, the authorities are, in order: the code
> itself, the "What is not implemented yet" section of `README.md`, the
> "Design canon vs. as-built" table in `CLAUDE.md`, and the implementation
> checklist in `doc/fix_operations.md`.

**The design target: a Rust implementation supporting FIX 4.0 through 5.0 SP2 with microsecond-scale latency and high message throughput.**

The financial trading ecosystem demands protocol implementations that combine absolute correctness with extreme performance. IronFix aims at single-digit microsecond latency through zero-copy parsing, SIMD-accelerated operations, arena allocation, and careful async/sync boundary management—while supporting all FIX protocol versions (4.0 through 5.0 SP2, FIXT 1.1) and FAST-encoded market data feeds. Of those techniques, zero-copy parsing and `memchr`-based (SIMD) delimiter search are implemented today; arena allocation and the sync/async split are not, and the latency goal is unverified.

---

## Architectural foundations and design philosophy

IronFix follows an OSI-layered architecture that strictly separates concerns, enabling independent optimization of each layer while maintaining clean interfaces between them. This design draws from lessons learned in QuickFIX (session management patterns), FerrumFIX (layered architecture), and Chronicle FIX (zero-GC techniques).

### Core design principles

The architecture prioritizes three often-competing goals through careful design choices:

**Zero-allocation hot paths** ensure that the critical order-entry path never allocates heap memory. Every message uses pre-allocated buffers from arena allocators, and parsed fields reference the original byte buffer through zero-copy slices. This eliminates allocation jitter that plagues garbage-collected implementations.
*Status: partially built. The tag=value decoder is zero-copy — parsed field values borrow the input buffer and are never copied — and the encoder targets a pre-allocated buffer. The decoder's field index is a `SmallVec<[FieldRef; 32]>` that stays inline for the first 32 fields and spills to the heap only for a message with more than 32 fields. Arena allocation is not implemented — there is no `bumpalo` dependency. Nothing is measured.*

**Compile-time correctness** leverages Rust's type system for session state machines (typestate pattern), message validation, and field access. Generated code from FIX dictionaries provides type-safe field accessors, catching errors at compile time rather than runtime.
*Status: partially built. The session FSM is a sealed typestate today. Generated field accessors are not: `ironfix-codegen` has no consumer and the `ironfix-derive` macros expand to `todo!()`, so field access is currently untyped tag lookup.*

**Flexible deployment** supports both ultra-low-latency synchronous modes (kernel bypass, busy-polling) and standard async Tokio patterns for applications where operational simplicity matters more than tail latency.
*Status: not built. IronFix is async-only. There is no synchronous mode, no kernel bypass and no busy-polling path.*

---

## Crate organization and module structure

> **Target tree, not the current one.** The workspace has 11 member crates and
> roughly 30 source files; the tree below names files and directories that do
> not exist. For the real layout, run `make tree` or read the crate map in
> `CLAUDE.md`. Notable differences: there is no `ironfix/` facade crate (the
> umbrella re-exports live in `ironfix-example`); `ironfix-transport` contains
> only `codec.rs`; `ironfix-store` contains only `traits.rs` and `memory.rs`;
> `ironfix-engine` has no `acceptor.rs` but does have `connection.rs`,
> `outbound.rs`, `error.rs` and a private `wire.rs`; `ironfix-session` has no
> `recovery.rs` and its FSM lives in `state.rs`; `ironfix-fast` has no
> `template.rs` or `dictionary.rs`; `ironfix-dictionary` has `loader.rs` /
> `schema.rs` / `validator.rs` and a single vendored `spec/FIX44.xml`.

```
ironfix/
├── Cargo.toml                    # Workspace manifest
├── ironfix/                      # Facade crate re-exporting public API
│   └── src/lib.rs
│
├── ironfix-core/                 # Fundamental types, traits, errors
│   └── src/
│       ├── lib.rs
│       ├── error.rs              # Error types, Result aliases
│       ├── types.rs              # SeqNum, Timestamp, CompID
│       ├── field.rs              # Field trait, FieldTag, FieldValue
│       └── message.rs            # Message trait, MsgType enum
│
├── ironfix-dictionary/           # FIX specification parsing
│   └── src/
│       ├── lib.rs
│       ├── parser.rs             # QuickFIX XML parser
│       ├── schema.rs             # Field/Message/Component definitions
│       ├── versions/             # Embedded dictionaries
│       │   ├── fix40.xml
│       │   ├── fix42.xml
│       │   ├── fix44.xml
│       │   └── fix50sp2.xml
│       └── validation.rs         # Runtime validation rules
│
├── ironfix-codegen/              # Build-time code generation
│   └── src/
│       ├── lib.rs
│       ├── generator.rs          # Rust source generator
│       ├── fields.rs             # Field constant generation
│       ├── messages.rs           # Message struct generation
│       └── components.rs         # Component trait generation
│
├── ironfix-derive/               # Procedural macros
│   └── src/
│       ├── lib.rs
│       ├── message.rs            # #[derive(FixMessage)]
│       └── field.rs              # #[derive(FixField)]
│
├── ironfix-tagvalue/             # Tag=value encoding layer
│   └── src/
│       ├── lib.rs
│       ├── decoder.rs            # Zero-copy FIX decoder
│       ├── encoder.rs            # FIX message encoder
│       ├── checksum.rs           # SIMD-accelerated checksum
│       └── raw_message.rs        # Unparsed message wrapper
│
├── ironfix-fast/                 # FAST protocol support
│   └── src/
│       ├── lib.rs
│       ├── decoder.rs            # FAST decoder state machine
│       ├── encoder.rs            # FAST encoder
│       ├── operators.rs          # Copy, Delta, Increment, etc.
│       ├── pmap.rs               # Presence map handling
│       ├── template.rs           # Template definitions
│       └── dictionary.rs         # Decoder state management
│
├── ironfix-session/              # Session layer protocol
│   └── src/
│       ├── lib.rs
│       ├── state_machine.rs      # Typestate session FSM
│       ├── sequence.rs           # Sequence number management
│       ├── heartbeat.rs          # Heartbeat/TestRequest logic
│       ├── recovery.rs           # Gap fill, ResendRequest
│       └── config.rs             # Session configuration
│
├── ironfix-transport/            # Network transport layer
│   └── src/
│       ├── lib.rs
│       ├── tcp/
│       │   ├── connector.rs      # TCP initiator
│       │   ├── acceptor.rs       # TCP acceptor
│       │   └── codec.rs          # Tokio codec implementation
│       ├── tls.rs                # rustls TLS wrapper
│       └── multicast.rs          # UDP multicast for FAST
│
├── ironfix-store/                # Message persistence
│   └── src/
│       ├── lib.rs
│       ├── traits.rs             # MessageStore trait
│       ├── memory.rs             # In-memory store
│       ├── file.rs               # File-based store
│       └── mmap.rs               # Memory-mapped store
│
├── ironfix-engine/               # High-level engine facade
│   └── src/
│       ├── lib.rs
│       ├── initiator.rs          # Client-side engine
│       ├── acceptor.rs           # Server-side engine
│       ├── application.rs        # Application callback trait
│       └── builder.rs            # Fluent configuration API
│
└── examples/
    ├── simple_initiator.rs
    ├── market_data_handler.rs
    └── benchmark.rs
```

---

## Core traits and abstractions

> The signatures below are the intended shape and do not all match the code.
> Read the crate docs on docs.rs, or `ironfix-core/src/`, for the real traits.

### Message representation

The message abstraction supports both zero-copy borrowed views (for hot-path processing) and owned representations (for storage and cross-thread transfer):

```rust
// ironfix-core/src/message.rs

/// Zero-copy view into a FIX message buffer
pub struct RawMessage<'a> {
    buffer: &'a [u8],
    begin_string: Range<usize>,
    body: Range<usize>,
    msg_type: MsgType,
    fields: SmallVec<[FieldRef<'a>; 32]>,
}

/// Reference to a single field without allocation
pub struct FieldRef<'a> {
    pub tag: u32,
    pub value: &'a [u8],
}

/// Owned message for storage/transfer
pub struct OwnedMessage {
    buffer: Bytes,
    msg_type: MsgType,
    field_offsets: Vec<(u32, Range<usize>)>,
}

/// Type-safe field access trait
pub trait FixMessage: Sized {
    const MSG_TYPE: &'static str;
    
    fn from_raw(raw: &RawMessage<'_>) -> Result<Self, DecodeError>;
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError>;
    
    fn get_field<F: FixField>(&self) -> Option<F::Value>;
    fn set_field<F: FixField>(&mut self, value: F::Value);
}
```

### Session management with typestate

The typestate pattern ensures session state transitions are checked at compile time:

```rust
// ironfix-session/src/state_machine.rs

/// Zero-sized marker types for session states
pub struct Disconnected;
pub struct Connecting;
pub struct LogonSent { sent_at: Instant }
pub struct Active;
pub struct Resending { gap: Range<u64> }
pub struct LogoutPending;

pub struct Session<S, Store: MessageStore> {
    config: SessionConfig,
    store: Store,
    next_sender_seq: AtomicU64,
    next_target_seq: AtomicU64,
    heartbeat_interval: Duration,
    last_received: Instant,
    _state: PhantomData<S>,
}

impl<Store: MessageStore> Session<Disconnected, Store> {
    pub fn connect(self, stream: TcpStream) -> Session<Connecting, Store> {
        // TCP connection established, ready for logon
    }
}

impl<Store: MessageStore> Session<Connecting, Store> {
    pub fn send_logon(self) -> Result<Session<LogonSent, Store>, SessionError> {
        // Build and send Logon message
        // Transition to LogonSent state
    }
}

impl<Store: MessageStore> Session<LogonSent, Store> {
    pub fn on_logon_ack(self, msg: &RawMessage<'_>) 
        -> Result<Session<Active, Store>, SessionError> 
    {
        // Validate Logon response
        // Check sequence numbers, initiate recovery if needed
    }
}

impl<Store: MessageStore> Session<Active, Store> {
    /// Only callable when session is active
    pub fn send_new_order(&mut self, order: &NewOrderSingle) 
        -> Result<u64, SessionError> 
    {
        let seq = self.next_sender_seq.fetch_add(1, Ordering::SeqCst);
        // Encode and send
        Ok(seq)
    }
    
    pub fn initiate_logout(self) -> Session<LogoutPending, Store> {
        // Send Logout message
    }
}
```

### Application callback interface

Following QuickFIX's proven pattern with async support:

```rust
// ironfix-engine/src/application.rs

#[async_trait]
pub trait Application: Send + Sync {
    /// Called when session is created
    async fn on_create(&self, session_id: &SessionId);
    
    /// Called on successful logon
    async fn on_logon(&self, session_id: &SessionId);
    
    /// Called on logout
    async fn on_logout(&self, session_id: &SessionId);
    
    /// Intercept outgoing admin messages (Logon, Heartbeat, etc.)
    async fn to_admin(&self, message: &mut OwnedMessage, session_id: &SessionId);
    
    /// Process incoming admin messages
    async fn from_admin(&self, message: &RawMessage<'_>, session_id: &SessionId) 
        -> Result<(), RejectReason>;
    
    /// Intercept outgoing application messages
    async fn to_app(&self, message: &mut OwnedMessage, session_id: &SessionId);
    
    /// Process incoming application messages (orders, executions)
    async fn from_app(&self, message: &RawMessage<'_>, session_id: &SessionId) 
        -> Result<(), RejectReason>;
}
```

### Message store abstraction

> The `MessageStore` trait and `MemoryStore` exist in `ironfix-store`, but
> **`ironfix-engine` never calls either**. No outbound message is persisted and
> no sequence number survives a restart, so resend-from-store is not
> implemented: an inbound `ResendRequest` is answered with a gap fill. There is
> no file-backed or memory-mapped store.

```rust
// ironfix-store/src/traits.rs

#[async_trait]
pub trait MessageStore: Send + Sync {
    /// Store outgoing message for potential resend
    async fn store(&self, seq_num: u64, message: &[u8]) -> Result<(), StoreError>;
    
    /// Retrieve messages for resend request
    async fn get_range(&self, begin: u64, end: u64) 
        -> Result<Vec<OwnedMessage>, StoreError>;
    
    /// Get/set sequence numbers
    fn next_sender_seq(&self) -> u64;
    fn next_target_seq(&self) -> u64;
    fn set_next_sender_seq(&self, seq: u64);
    fn set_next_target_seq(&self, seq: u64);
    
    /// Reset sequence numbers (new session)
    async fn reset(&self) -> Result<(), StoreError>;
}

/// High-performance memory-mapped store for persistence
pub struct MmapStore {
    mmap: MmapMut,
    header: *mut StoreHeader,
    messages: SegQueue<(u64, Range<usize>)>,
}
```

---

## Data flow architecture

### Order entry path (initiator, hot path)

> The real path is simpler and entirely async: `Application` builds an
> `OutboundMessage`, `Connection::send` queues it on a tokio mpsc, the
> `Initiator`'s background reactor stamps the header/`MsgSeqNum`/trailer via the
> private `wire::MessageFactory`, encodes with `ironfix-tagvalue`, and writes
> through `FixCodec` on a `TcpStream`. There is no io_uring, no `SO_BUSY_POLL`,
> no hardware timestamping, and no store write. The target latency below is a
> goal, not a measurement.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ORDER ENTRY DATA FLOW                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Application Thread                                                          │
│  ┌──────────────────┐                                                        │
│  │  NewOrderSingle  │ ← User creates order (stack-allocated)                │
│  └────────┬─────────┘                                                        │
│           │                                                                  │
│           ▼                                                                  │
│  ┌──────────────────┐                                                        │
│  │    Encoder       │ ← Zero-copy encode into pre-allocated buffer          │
│  │  (arena alloc)   │   Header: 8=FIX.4.4|9=XXX|35=D|49=...|56=...|34=N|    │
│  └────────┬─────────┘   Body: 11=ClOrdID|55=AAPL|54=1|38=100|40=2|44=150|   │
│           │             Trailer: 10=XXX|                                     │
│           ▼                                                                  │
│  ┌──────────────────┐                                                        │
│  │  Session Layer   │ ← Assign sequence number (atomic increment)           │
│  │  (seq num mgmt)  │   Store message in MmapStore (async, non-blocking)    │
│  └────────┬─────────┘                                                        │
│           │                                                                  │
│           ▼                                                                  │
│  ┌──────────────────┐                                                        │
│  │    TCP Write     │ ← TCP_NODELAY enabled, write to kernel buffer         │
│  │  (sync/io_uring) │   Optional: SO_BUSY_POLL for busy-wait               │
│  └────────┬─────────┘                                                        │
│           │                                                                  │
│           ▼                                                                  │
│  ┌──────────────────┐                                                        │
│  │   NIC Transmit   │ ← Hardware timestamp captured                         │
│  └──────────────────┘                                                        │
│                                                                              │
│  Target Latency: <10μs from order creation to NIC transmit                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Market data reception (FAST multicast)

> **Not built.** There is no multicast receiver and no A/B arbitration anywhere
> in the workspace. `ironfix-fast` exposes decode primitives that a caller must
> drive itself; see the `fast_*` examples.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      MARKET DATA RECEPTION FLOW                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Feed A (Primary)              Feed B (Secondary)                           │
│  ┌───────────────┐             ┌───────────────┐                            │
│  │ UDP Multicast │             │ UDP Multicast │                            │
│  │ 239.1.1.1:9001│             │ 239.1.1.2:9001│                            │
│  └───────┬───────┘             └───────┬───────┘                            │
│          │                             │                                     │
│          └──────────┬──────────────────┘                                     │
│                     ▼                                                        │
│          ┌───────────────────┐                                               │
│          │  Line Arbitrator  │ ← Sequence-based dedup (4-byte preamble)     │
│          │  (A/B feed merge) │   Emit first-arriving of each seq num        │
│          └─────────┬─────────┘                                               │
│                    │                                                         │
│                    ▼                                                         │
│          ┌───────────────────┐                                               │
│          │   FAST Decoder    │ ← Template lookup, operator application      │
│          │  (stateful dict)  │   Zero-copy field extraction                 │
│          └─────────┬─────────┘                                               │
│                    │                                                         │
│                    ▼                                                         │
│          ┌───────────────────┐                                               │
│          │   Gap Detector    │ ← Track per-instrument RptSeq                │
│          │  (recovery mgr)   │   Queue recovery if gap detected             │
│          └─────────┬─────────┘                                               │
│                    │                                                         │
│          ┌────────┴────────┐                                                │
│          ▼                 ▼                                                │
│  ┌───────────────┐  ┌────────────────┐                                      │
│  │ Order Book    │  │ SPSC Channel   │ ← Lock-free to strategy thread       │
│  │ Builder       │  │ (crossbeam)    │                                       │
│  └───────────────┘  └────────────────┘                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Session layer state transitions

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     FIX SESSION STATE MACHINE                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                        ┌─────────────────┐                                   │
│                        │   Disconnected  │◄───────────────────────────┐     │
│                        └────────┬────────┘                            │     │
│                                 │ connect()                           │     │
│                                 ▼                                     │     │
│                        ┌─────────────────┐                            │     │
│                        │   Connecting    │                            │     │
│                        └────────┬────────┘                            │     │
│                                 │ send_logon()                        │     │
│                                 ▼                                     │     │
│                        ┌─────────────────┐     Timeout/               │     │
│                   ┌───►│   LogonSent     │─────Reject────────────────►│     │
│                   │    └────────┬────────┘                            │     │
│                   │             │ on_logon_ack()                      │     │
│                   │             ▼                                     │     │
│                   │    ┌─────────────────┐                            │     │
│                   │    │     Active      │◄────────────────────┐      │     │
│                   │    └───┬───────┬─────┘                     │      │     │
│                   │        │       │                           │      │     │
│        Recovery   │        │       │ Gap detected              │      │     │
│        complete   │        │       ▼                           │      │     │
│                   │        │  ┌──────────────┐                 │      │     │
│                   └────────┼──│  Resending   │─────────────────┘      │     │
│                            │  │  (gap fill)  │  Gap filled            │     │
│                            │  └──────────────┘                        │     │
│                            │                                          │     │
│                            │ initiate_logout()                        │     │
│                            ▼                                          │     │
│                   ┌─────────────────┐                                 │     │
│                   │ LogoutPending   │─────────────────────────────────┘     │
│                   └─────────────────┘  Logout ack / Timeout                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Key implementation decisions

> These are proposed decisions. Each carries a **Status** line saying whether it
> is built. Rationale figures quoted in this section are estimates from the
> literature, not measurements of IronFix.

### Decision 1: Hybrid sync/async architecture

**Status: not built.** IronFix is async-only. There is no hot/warm path split, no pinned thread, no busy-poll and no `HotPathSender`.

**Rationale**: Tokio's cooperative scheduling introduces **50-200μs** latency variance in worst cases. For ultra-low-latency order entry, this is unacceptable. However, async patterns excel for connection management, heartbeats, and market data aggregation.

**Implementation**:

```rust
pub struct IronFixEngine {
    /// Hot path: synchronous, pinned thread, busy-poll
    order_sender: HotPathSender,
    
    /// Warm path: Tokio current_thread runtime per session
    session_runtimes: Vec<Runtime>,
    
    /// Cold path: Shared multi-threaded runtime
    background_runtime: Runtime,
}

impl IronFixEngine {
    pub fn send_order_sync(&self, order: &NewOrderSingle) -> Result<u64, Error> {
        // Direct syscall path, no async overhead
        // Uses SO_BUSY_POLL for minimal latency
        self.order_sender.send_blocking(order)
    }
    
    pub async fn send_order_async(&self, order: NewOrderSingle) -> Result<u64, Error> {
        // Standard async path for non-latency-critical applications
        self.order_sender.send(order).await
    }
}
```

### Decision 2: Zero-copy parsing with memchr SIMD acceleration

**Status: built**, in `ironfix-tagvalue::Decoder`, though without the hand-written `unsafe` AVX2 checksum sketched below — the workspace contains zero `unsafe`. The speedup figure is not an IronFix measurement.

**Rationale**: FIX messages use SOH (0x01) delimiters and '=' separators. SIMD-accelerated search via `memchr` provides **6-10x speedup** over naive iteration.

**Implementation**:

```rust
// ironfix-tagvalue/src/decoder.rs

use memchr::{memchr, memchr2};

pub struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    /// Parse next field without allocation
    #[inline(always)]
    pub fn next_field(&mut self) -> Option<FieldRef<'a>> {
        if self.offset >= self.input.len() {
            return None;
        }
        
        let remaining = &self.input[self.offset..];
        
        // SIMD-accelerated search for '=' delimiter
        let eq_pos = memchr(b'=', remaining)?;
        let tag_bytes = &remaining[..eq_pos];
        
        // SIMD-accelerated search for SOH delimiter  
        let soh_pos = memchr(0x01, &remaining[eq_pos + 1..])?;
        let value = &remaining[eq_pos + 1..eq_pos + 1 + soh_pos];
        
        self.offset += eq_pos + 1 + soh_pos + 1;
        
        Some(FieldRef {
            tag: parse_tag(tag_bytes)?,
            value,
        })
    }
}

/// SIMD-accelerated checksum calculation
#[cfg(target_arch = "x86_64")]
pub fn calculate_checksum(data: &[u8]) -> u8 {
    use std::arch::x86_64::*;
    
    unsafe {
        let mut sum = _mm256_setzero_si256();
        let mut offset = 0;
        
        // Process 32 bytes at a time with AVX2
        while offset + 32 <= data.len() {
            let chunk = _mm256_loadu_si256(data[offset..].as_ptr() as *const _);
            // Use SAD instruction for horizontal byte sum
            sum = _mm256_add_epi64(sum, _mm256_sad_epu8(chunk, _mm256_setzero_si256()));
            offset += 32;
        }
        
        // Extract horizontal sum
        let mut total: u64 = 0;
        let arr: [u64; 4] = std::mem::transmute(sum);
        total = arr.iter().sum();
        
        // Handle remainder
        total += data[offset..].iter().map(|&b| b as u64).sum::<u64>();
        
        (total % 256) as u8
    }
}
```

### Decision 3: Arena allocation for message processing

**Status: not built.** There is no `bumpalo` dependency in the workspace. Per-message allocation is avoided instead by zero-copy borrowed slices, a pre-allocated encode buffer, and `smallvec`/`arrayvec` for bounded field sets.

**Rationale**: Per-message heap allocation causes unpredictable latency. Arena allocators provide **O(1) allocation** and **O(1) mass deallocation** after message processing.

**Implementation**:

```rust
use bumpalo::Bump;

pub struct MessageProcessor {
    arena: Bump,
    field_buffer: bumpalo::collections::Vec<'static, FieldRef<'static>>,
}

impl MessageProcessor {
    pub fn process_message(&mut self, raw: &[u8]) -> Result<(), Error> {
        // All allocations use the arena
        let mut decoder = Decoder::new(raw);
        let fields: bumpalo::collections::Vec<FieldRef> = 
            bumpalo::collections::Vec::new_in(&self.arena);
        
        while let Some(field) = decoder.next_field() {
            fields.push(field);
        }
        
        // Process message...
        let result = self.handle_fields(&fields)?;
        
        // Mass deallocation - single pointer reset, no Drop calls
        self.arena.reset();
        
        Ok(result)
    }
}
```

### Decision 4: Code generation with runtime fallback

**Status: only the fallback is built.** The runtime dictionary path (`ironfix-dictionary`) works, but nothing consumes generated code: `ironfix-codegen` has no in-workspace consumer and the `ironfix-derive` macros expand to `todo!()`. The `#[derive(FixMessage)]` example below therefore does not work today.

**Rationale**: Generated code provides type safety and compile-time validation, but runtime dictionary support enables flexibility for custom tags and exchange-specific variations.

**Build-time generation** (`build.rs`):

```rust
// ironfix-codegen/src/generator.rs

pub fn generate_from_dictionary(dict: &Dictionary, output: &Path) -> Result<()> {
    let mut code = String::new();
    
    // Generate field constants
    code.push_str("pub mod fields {\n");
    for field in dict.fields() {
        code.push_str(&format!(
            "    pub const {}: u32 = {};\n",
            field.name.to_shouty_snake_case(),
            field.number
        ));
    }
    code.push_str("}\n\n");
    
    // Generate message structs
    for msg in dict.messages() {
        code.push_str(&generate_message_struct(msg, dict)?);
    }
    
    std::fs::write(output, code)?;
    Ok(())
}

fn generate_message_struct(msg: &MessageDef, dict: &Dictionary) -> Result<String> {
    let mut code = format!(
        r#"
#[derive(Debug, Clone, FixMessage)]
#[fix(msg_type = "{}")]
pub struct {} {{
"#,
        msg.msg_type, msg.name
    );
    
    for field in &msg.fields {
        let rust_type = field_to_rust_type(&field.field_type);
        let optional = if field.required { "" } else { "Option<" };
        let optional_end = if field.required { "" } else { ">" };
        
        code.push_str(&format!(
            "    #[fix(tag = {})]\n    pub {}: {}{}{},\n",
            field.tag, field.name.to_snake_case(), optional, rust_type, optional_end
        ));
    }
    
    code.push_str("}\n");
    Ok(code)
}
```

**Generated output example**:

```rust
// Generated from FIX44.xml

pub mod fields {
    pub const BEGIN_STRING: u32 = 8;
    pub const BODY_LENGTH: u32 = 9;
    pub const MSG_TYPE: u32 = 35;
    pub const CL_ORD_ID: u32 = 11;
    pub const SYMBOL: u32 = 55;
    pub const SIDE: u32 = 54;
    pub const ORDER_QTY: u32 = 38;
    pub const ORD_TYPE: u32 = 40;
    pub const PRICE: u32 = 44;
    // ... 1000+ fields
}

#[derive(Debug, Clone, FixMessage)]
#[fix(msg_type = "D")]
pub struct NewOrderSingle {
    #[fix(tag = 11)]
    pub cl_ord_id: ArrayString<20>,
    
    #[fix(tag = 1)]
    pub account: Option<ArrayString<20>>,
    
    #[fix(tag = 55)]
    pub symbol: ArrayString<8>,
    
    #[fix(tag = 54)]
    pub side: Side,
    
    #[fix(tag = 60)]
    pub transact_time: Timestamp,
    
    #[fix(tag = 38)]
    pub order_qty: Decimal,
    
    #[fix(tag = 40)]
    pub ord_type: OrdType,
    
    #[fix(tag = 44)]
    pub price: Option<Decimal>,
}
```

### Decision 5: FAST decoder with compiled templates

**Status: not built.** `ironfix-fast` implements the primitives only — stop-bit encoding, presence maps and the field operators. There is no template XML parser, no compiled template, no UDP multicast receiver, and no wiring into the session or engine path.

**Rationale**: FAST decoding is stateful (previous values dictionary) and template-driven. Pre-compiling templates into optimized decode functions eliminates interpretation overhead.

```rust
// ironfix-fast/src/decoder.rs

pub struct FastDecoder {
    templates: HashMap<u32, CompiledTemplate>,
    global_dict: Dictionary,
    template_dicts: HashMap<u32, Dictionary>,
}

struct CompiledTemplate {
    id: u32,
    name: String,
    decode_fn: fn(&mut FastDecoder, &[u8], &mut usize) -> Result<DecodedMessage, FastError>,
}

impl FastDecoder {
    pub fn decode(&mut self, data: &[u8]) -> Result<DecodedMessage, FastError> {
        let mut offset = 0;
        
        // Decode presence map
        let pmap = PresenceMap::decode(data, &mut offset)?;
        
        // Template ID (first pmap bit)
        let template_id = if pmap.bit(0) {
            decode_uint(data, &mut offset)? as u32
        } else {
            self.last_template_id
        };
        self.last_template_id = template_id;
        
        // Dispatch to compiled decode function
        let template = self.templates.get(&template_id)
            .ok_or(FastError::UnknownTemplate(template_id))?;
        
        (template.decode_fn)(self, data, &mut offset)
    }
}

/// Operator implementations
impl FastDecoder {
    #[inline(always)]
    fn apply_copy<T: Clone>(&mut self, key: &str, pmap_bit: bool, 
                            stream_value: Option<T>, initial: Option<T>) 
        -> Result<Option<T>, FastError> 
    {
        if pmap_bit {
            match stream_value {
                Some(v) => {
                    self.global_dict.set(key, v.clone());
                    Ok(Some(v))
                }
                None => {
                    self.global_dict.set_empty(key);
                    Ok(None)
                }
            }
        } else {
            match self.global_dict.get(key) {
                Some(v) => Ok(Some(v.clone())),
                None => Ok(initial),
            }
        }
    }
    
    #[inline(always)]
    fn apply_delta_i64(&mut self, key: &str, delta: i64) -> Result<i64, FastError> {
        let prev = self.global_dict.get_i64(key).unwrap_or(0);
        let new_value = prev + delta;
        self.global_dict.set_i64(key, new_value);
        Ok(new_value)
    }
}
```

---

## Performance optimization strategies

> **None of this section is implemented, and none of it is measured.** There is
> no socket-tuning helper, no `libc`/`core_affinity` dependency, and no lock-free
> ring buffer on the message path beyond the `crossbeam` channels used by the
> examples. The criterion harness that now exists covers the codec hot paths, not
> any of the socket or affinity work sketched here. Treat the whole section as a
> wish list with sketches.

### TCP socket configuration

```rust
// ironfix-transport/src/tcp/connector.rs

pub fn configure_low_latency_socket(stream: &TcpStream) -> io::Result<()> {
    use socket2::Socket;
    let socket = Socket::from(stream.try_clone()?);
    
    // Disable Nagle's algorithm - send immediately
    socket.set_nodelay(true)?;
    
    // Appropriately sized buffers
    socket.set_recv_buffer_size(256 * 1024)?;  // 256KB
    socket.set_send_buffer_size(256 * 1024)?;
    
    // TCP keepalive for connection health
    socket.set_keepalive(true)?;
    
    // On Linux: Enable busy polling (requires root or CAP_NET_ADMIN)
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let timeout: libc::c_int = 50; // microseconds
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BUSY_POLL,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of_val(&timeout) as libc::socklen_t,
            );
        }
    }
    
    Ok(())
}
```

### Lock-free message passing

```rust
// Inter-thread communication without locks

use crossbeam_channel::{bounded, Sender, Receiver};
use crossbeam_queue::ArrayQueue;

pub struct MarketDataPipeline {
    // SPSC queue for decoded market data
    decoded_queue: ArrayQueue<MarketDataUpdate>,
    
    // MPSC channel for strategy signals
    strategy_tx: Sender<StrategySignal>,
    strategy_rx: Receiver<StrategySignal>,
}

impl MarketDataPipeline {
    pub fn new(capacity: usize) -> Self {
        let (strategy_tx, strategy_rx) = bounded(capacity);
        Self {
            decoded_queue: ArrayQueue::new(capacity),
            strategy_tx,
            strategy_rx,
        }
    }
    
    /// Called from decoder thread - non-blocking push
    #[inline]
    pub fn publish_update(&self, update: MarketDataUpdate) -> Result<(), MarketDataUpdate> {
        self.decoded_queue.push(update)
    }
    
    /// Called from strategy thread - non-blocking pop
    #[inline]
    pub fn try_receive(&self) -> Option<MarketDataUpdate> {
        self.decoded_queue.pop()
    }
}
```

### Memory layout optimization

**Illustrative layout sketch.** The `avg_px: f64` and `prices: [f64; 8]` fields
below are plain `f64` only to keep the padding and SIMD-batch narrative legible;
they contradict the Decimal-for-money rule and would not appear in production
code. Real monetary values in IronFix are `rust_decimal::Decimal`, never `f64` —
a production `OrderState` would carry `Decimal`, which changes this exact byte
layout.

```rust
// Cache-friendly structures for hot path

/// Fields ordered by size descending to minimize padding
#[repr(C)]
pub struct OrderState {
    pub cl_ord_id: u64,           // 8 bytes
    pub order_id: u64,            // 8 bytes
    pub cum_qty: u64,             // 8 bytes
    pub leaves_qty: u64,          // 8 bytes
    pub avg_px: f64,              // 8 bytes
    pub transact_time: u64,       // 8 bytes (epoch nanos)
    pub ord_status: OrdStatus,    // 1 byte
    pub side: Side,               // 1 byte
    pub _padding: [u8; 6],        // Explicit padding
}  // Total: 56 bytes, cache-line friendly

/// Array-of-Structs to Struct-of-Arrays for SIMD-friendly access
#[repr(C, align(64))]  // Cache line aligned
pub struct OrderBookLevel {
    pub prices: [f64; 8],    // SIMD-friendly batch
    pub sizes: [u64; 8],
    pub count: [u32; 8],
}
```

### Compile-time optimizations

```toml
# Cargo.toml profile for production

[profile.release]
opt-level = 3
lto = "fat"              # Link-time optimization across crates
codegen-units = 1        # Better optimization, slower compile
panic = "abort"          # No unwinding overhead
strip = true             # Smaller binary

[profile.release.build-override]
opt-level = 3

# Target-specific optimization
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "target-cpu=native"]
```

---

## FIX version support matrix

> **What "support" means today.** The session layer is parameterised by
> `BeginString` and each version below has a runnable client/server example
> pair, so the session handshake is exercised for all of them. But **only FIX
> 4.4 ships an embedded dictionary** (`ironfix-dictionary/spec/FIX44.xml`,
> vendored from QuickFIX); every other version requires you to supply the
> QuickFIX XML yourself via `Dictionary::from_quickfix_xml`. And the `Validator`
> is never invoked by the engine or the codec, so no version is schema-validated
> automatically. The "Key Characteristics" column below is background on the FIX
> specification, not a statement about IronFix coverage.

| Version | BeginString | Transport | Key Characteristics |
|---------|-------------|-----------|---------------------|
| FIX 4.0 | `FIX.4.0` | Combined | Original, deprecated |
| FIX 4.1 | `FIX.4.1` | Combined | Basic multi-leg |
| FIX 4.2 | `FIX.4.2` | Combined | Widely used, equities/FX |
| FIX 4.3 | `FIX.4.3` | Combined | Parties component introduced |
| FIX 4.4 | `FIX.4.4` | Combined | Most adopted, multi-asset |
| FIX 5.0 | `FIXT.1.1` | Separate | Transport independence |
| FIX 5.0 SP1 | `FIXT.1.1` | Separate | First service pack |
| FIX 5.0 SP2 | `FIXT.1.1` | Separate | Extension packs applied |

**FIXT 1.1 handling**: For FIX 5.0+, the session layer uses `FIXT.1.1` BeginString while application messages carry an `ApplVerID` tag indicating the application version (`7`=5.0, `8`=5.0SP1, `9`=5.0SP2).

---

## Critical code patterns

> Sketches, not extracts. The shipped `FixCodec` in `ironfix-transport` differs
> from the version below — notably it bounds its read buffer, verifies the
> trailer unconditionally, and follows the garbled-message recovery policy
> documented in `doc/fix_operations.md`. Repeating-group parsing driven by a
> dictionary lives in `ironfix-dictionary::Validator`, not in the decoder, which
> is deliberately schema-free.

### Tokio codec for FIX framing

```rust
// ironfix-transport/src/tcp/codec.rs

use tokio_util::codec::{Decoder, Encoder};
use bytes::{BytesMut, Buf, BufMut};

pub struct FixCodec {
    max_message_size: usize,
    checksum_validation: bool,
}

impl Decoder for FixCodec {
    type Item = RawMessage;
    type Error = CodecError;
    
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Minimum FIX message: 8=FIX.4.2|9=5|35=0|10=XXX| (~30 bytes)
        if src.len() < 30 {
            return Ok(None);
        }
        
        // Find BeginString (must start with "8=")
        if &src[0..2] != b"8=" {
            return Err(CodecError::InvalidBeginString);
        }
        
        // Find BodyLength field (9=XXX|)
        let body_len_start = memchr(0x01, src).ok_or(CodecError::Incomplete)? + 1;
        if &src[body_len_start..body_len_start + 2] != b"9=" {
            return Err(CodecError::MissingBodyLength);
        }
        
        let body_len_end = memchr(0x01, &src[body_len_start..])
            .ok_or(CodecError::Incomplete)? + body_len_start;
        
        let body_length: usize = std::str::from_utf8(&src[body_len_start + 2..body_len_end])
            .map_err(|_| CodecError::InvalidBodyLength)?
            .parse()
            .map_err(|_| CodecError::InvalidBodyLength)?;
        
        // Calculate total message length
        // BodyLength counts from after 9=XXX| to before 10=
        let total_length = body_len_end + 1 + body_length + 7; // +7 for |10=XXX|
        
        if src.len() < total_length {
            // Reserve capacity hint for efficiency
            src.reserve(total_length - src.len());
            return Ok(None);
        }
        
        // Validate checksum if enabled
        if self.checksum_validation {
            let calculated = calculate_checksum(&src[..total_length - 7]);
            let declared = parse_checksum(&src[total_length - 4..total_length - 1])?;
            if calculated != declared {
                return Err(CodecError::ChecksumMismatch { calculated, declared });
            }
        }
        
        // Extract message without copying
        let message_bytes = src.split_to(total_length).freeze();
        
        Ok(Some(RawMessage::from_bytes(message_bytes)?))
    }
}

impl Encoder<&OwnedMessage> for FixCodec {
    type Error = CodecError;
    
    fn encode(&mut self, msg: &OwnedMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(msg.len());
        dst.put_slice(msg.as_bytes());
        Ok(())
    }
}
```

### Repeating group parsing

```rust
// ironfix-tagvalue/src/decoder.rs

pub struct GroupDecoder<'a> {
    raw: &'a RawMessage<'a>,
    group_def: &'static GroupDefinition,
    entries: SmallVec<[GroupEntry<'a>; 8]>,
}

impl<'a> GroupDecoder<'a> {
    pub fn decode(
        raw: &'a RawMessage<'a>,
        count_tag: u32,
        delimiter_tag: u32,
        member_tags: &'static [u32],
    ) -> Result<Self, DecodeError> {
        let count = raw.get_field_as::<u32>(count_tag)?;
        let mut entries = SmallVec::new();
        let mut current_entry = GroupEntry::new();
        let mut in_group = false;
        
        for field in raw.fields() {
            if field.tag == delimiter_tag {
                if in_group {
                    entries.push(std::mem::replace(&mut current_entry, GroupEntry::new()));
                }
                in_group = true;
                current_entry.add_field(field);
            } else if in_group && member_tags.contains(&field.tag) {
                current_entry.add_field(field);
            } else if in_group {
                // Non-member tag signals end of group
                entries.push(std::mem::take(&mut current_entry));
                break;
            }
        }
        
        if entries.len() != count as usize {
            return Err(DecodeError::GroupCountMismatch {
                expected: count,
                actual: entries.len() as u32,
            });
        }
        
        Ok(Self { raw, group_def, entries })
    }
}
```

### Session heartbeat management

```rust
// ironfix-session/src/heartbeat.rs

use tokio::time::{interval, Duration, Instant};

pub struct HeartbeatManager {
    interval: Duration,
    last_sent: Instant,
    last_received: Instant,
    test_request_pending: Option<String>,
}

impl HeartbeatManager {
    pub async fn run(
        &mut self,
        session: &mut ActiveSession,
    ) -> Result<(), SessionError> {
        let mut ticker = interval(Duration::from_secs(1));
        
        loop {
            ticker.tick().await;
            
            let now = Instant::now();
            let since_received = now.duration_since(self.last_received);
            let since_sent = now.duration_since(self.last_sent);
            
            // Check for missed heartbeat response
            if let Some(ref test_req_id) = self.test_request_pending {
                if since_received > self.interval * 2 {
                    return Err(SessionError::HeartbeatTimeout);
                }
            }
            
            // Send TestRequest if no message received
            if since_received > self.interval + Duration::from_secs(1) {
                if self.test_request_pending.is_none() {
                    let test_req_id = generate_test_req_id();
                    session.send_test_request(&test_req_id).await?;
                    self.test_request_pending = Some(test_req_id);
                }
            }
            
            // Send Heartbeat if nothing sent recently
            if since_sent > self.interval {
                session.send_heartbeat(None).await?;
                self.last_sent = Instant::now();
            }
        }
    }
    
    pub fn on_message_received(&mut self, msg: &RawMessage<'_>) {
        self.last_received = Instant::now();
        
        // Clear pending TestRequest if Heartbeat received
        if msg.msg_type() == MsgType::Heartbeat {
            if let Some(pending) = &self.test_request_pending {
                if let Some(test_req_id) = msg.get_field_str(fields::TEST_REQ_ID) {
                    if test_req_id == pending {
                        self.test_request_pending = None;
                    }
                }
            }
        }
    }
}
```

---

## Testing and certification strategy

> **Aspirational.** The workspace currently tests with inline `#[cfg(test)]`
> modules (the house convention) plus cross-crate end-to-end tests in
> `ironfix-engine/tests/initiator_tests.rs`, which drive a real `TcpListener`
> and `Framed<TcpStream, FixCodec>` against `Initiator`. There is no conformance
> test framework and no certification suite of the shape described below.

### Conformance test framework

```rust
// tests/conformance/mod.rs

pub struct ConformanceTestRunner {
    engine: TestEngine,
    scenarios: Vec<ConformanceScenario>,
}

impl ConformanceTestRunner {
    pub async fn run_logon_scenarios(&mut self) -> TestResults {
        let scenarios = vec![
            // Standard logon flow
            Scenario::new("standard_logon")
                .send(logon_message(seq: 1, heartbeat: 30))
                .expect_receive(logon_ack())
                .assert_state(SessionState::Active),
            
            // Logon with sequence reset
            Scenario::new("logon_reset_seq")
                .send(logon_message(seq: 1, reset_seq: true))
                .expect_receive(logon_ack())
                .assert_sender_seq(1)
                .assert_target_seq(1),
            
            // Logon with higher than expected sequence
            Scenario::new("logon_gap_fill")
                .set_expected_target_seq(5)
                .send(logon_message(seq: 10))
                .expect_receive(logon_ack())
                .expect_receive(resend_request(begin: 5, end: 9)),
            
            // Invalid credentials
            Scenario::new("logon_invalid_creds")
                .send(logon_message(username: "invalid"))
                .expect_receive(logout_with_text("Invalid credentials"))
                .expect_disconnect(),
        ];
        
        self.run_scenarios(scenarios).await
    }
    
    pub async fn run_sequence_scenarios(&mut self) -> TestResults {
        let scenarios = vec![
            // Normal sequence flow
            Scenario::new("normal_sequence")
                .establish_session()
                .send(new_order_single(seq: 2))
                .expect_receive(execution_report()),
            
            // Sequence gap triggers ResendRequest
            Scenario::new("sequence_gap")
                .establish_session()
                .send(new_order_single(seq: 5))  // Gap: 2,3,4
                .expect_receive(resend_request(begin: 2, end: 4)),
            
            // PossDupFlag handling
            Scenario::new("poss_dup")
                .establish_session()
                .send(execution_report(seq: 2, poss_dup: true, orig_time: past))
                .assert_processed_once(),
        ];
        
        self.run_scenarios(scenarios).await
    }
}
```

### Performance benchmarking

> **A criterion harness now exists, though not in the exact shape sketched
> below.** `ironfix-tagvalue`, `ironfix-fast` and `ironfix-transport` each carry
> a `benches/` target and `make bench` runs them. What it does *not* yet have is
> a recorded baseline or any published figure, so IronFix still has no
> performance data that may be stated as fact — run `make bench` on hardware you
> name to produce your own. The sketch below is illustrative; the real benches
> live in each crate's `benches/` directory. See `doc/adr/0001-criterion-benchmark-harness.md`
> for the decision to adopt criterion as a dev-only dependency.

```rust
// benches/parsing.rs

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

fn benchmark_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("FIX Parsing");
    
    // Sample NewOrderSingle message
    let nos_message = b"8=FIX.4.4\x019=148\x0135=D\x0149=SENDER\x01\
        56=TARGET\x0134=2\x0152=20251027-10:30:00.000\x01\
        11=ORDER123\x0155=AAPL\x0154=1\x0138=100\x0140=2\x0144=150.50\x01\
        60=20251027-10:30:00.000\x0110=123\x01";
    
    group.throughput(Throughput::Bytes(nos_message.len() as u64));
    
    group.bench_function("zero_copy_parse", |b| {
        b.iter(|| {
            let decoder = Decoder::new(nos_message);
            let msg = decoder.decode().unwrap();
            criterion::black_box(msg.msg_type());
        })
    });
    
    group.bench_function("checksum_simd", |b| {
        b.iter(|| {
            criterion::black_box(calculate_checksum(&nos_message[..nos_message.len()-7]))
        })
    });
    
    group.bench_function("field_extraction", |b| {
        let decoder = Decoder::new(nos_message);
        let msg = decoder.decode().unwrap();
        b.iter(|| {
            criterion::black_box(msg.get_field::<String>(fields::CL_ORD_ID))
        })
    });
    
    group.finish();
}

fn benchmark_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("FIX Encoding");
    
    let order = NewOrderSingle {
        cl_ord_id: "ORDER123".into(),
        symbol: "AAPL".into(),
        side: Side::Buy,
        order_qty: dec!(100),
        ord_type: OrdType::Limit,
        price: Some(dec!(150.50)),
        transact_time: Timestamp::now(),
    };
    
    group.bench_function("encode_nos", |b| {
        let mut buf = BytesMut::with_capacity(256);
        b.iter(|| {
            buf.clear();
            order.encode(&mut Encoder::new(&mut buf)).unwrap();
            criterion::black_box(buf.len())
        })
    });
    
    group.finish();
}

criterion_group!(benches, benchmark_parsing, benchmark_encoding);
criterion_main!(benches);
```

---

## Deployment considerations

> **Aspirational.** Nothing in this section is wired into IronFix: there is no
> thread pinning, no NUMA-aware allocation and no code that reads or requires
> the host tuning below. The `Docker/` directory builds the example servers as
> static musl binaries on Alpine; that is the whole deployment story today.

### System tuning for production

```bash
# CPU isolation for trading threads
# /etc/default/grub: GRUB_CMDLINE_LINUX="isolcpus=2,3 nohz_full=2,3"

# Disable CPU frequency scaling
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Disable C-states (idle states add wake latency)
echo 1 | tee /sys/devices/system/cpu/cpu*/cpustate/state*/disable

# Network tuning
sysctl -w net.core.busy_read=50
sysctl -w net.core.busy_poll=50
sysctl -w net.ipv4.tcp_low_latency=1
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216

# NIC tuning
ethtool -C eth0 rx-usecs 0 tx-usecs 0  # Disable interrupt coalescing
ethtool -K eth0 tso off lro off gro off  # Disable offloads that add latency
```

### Thread affinity configuration

```rust
// Application startup

fn configure_thread_affinity() {
    use core_affinity::CoreId;
    
    // Pin network I/O thread to core adjacent to NIC IRQ
    let network_thread = std::thread::Builder::new()
        .name("fix-network".into())
        .spawn(move || {
            core_affinity::set_for_current(CoreId { id: 2 });
            run_network_loop();
        });
    
    // Pin session thread
    let session_thread = std::thread::Builder::new()
        .name("fix-session".into())
        .spawn(move || {
            core_affinity::set_for_current(CoreId { id: 3 });
            run_session_loop();
        });
    
    // NUMA-aware memory allocation
    #[cfg(target_os = "linux")]
    {
        use libc::{numa_alloc_onnode, numa_node_of_cpu};
        let node = unsafe { numa_node_of_cpu(2) };
        // Allocate message buffers on same NUMA node as network core
    }
}
```

---

## Implementation roadmap

> **Historical plan, not a schedule and not a status report.** The week ranges
> below were the original estimate and have no bearing on when anything will
> land; do not quote them as commitments. Work has not followed this order —
> for example, `ironfix-engine`'s `Initiator` (listed under Phase 6) exists
> while file-based stores (Phase 2), TLS and the TCP connector/acceptor
> (Phase 3), the FAST template parser and multicast (Phase 4) and the code
> generation consumers (Phase 5) do not.
>
> The living checklist is the "Implementation Priority" section of
> `doc/fix_operations.md`. There is no `doc/ROADMAP.md`.

**Phase 1 - Core Foundation (Weeks 1-4)**
- `ironfix-core`: Base types, error handling, field definitions
- `ironfix-dictionary`: XML parser, embedded FIX 4.2/4.4 dictionaries
- `ironfix-tagvalue`: Zero-copy decoder with SIMD checksum
- Basic encoder with pre-allocated buffers

**Phase 2 - Session Layer (Weeks 5-8)**
- `ironfix-session`: Typestate state machine
- Sequence number management with atomic operations
- Heartbeat/TestRequest handling
- Gap fill and ResendRequest logic
- `ironfix-store`: Memory and file-based message stores

**Phase 3 - Transport Layer (Weeks 9-12)**
- `ironfix-transport`: TCP connector/acceptor with Tokio
- TLS support via rustls
- FixCodec for Tokio framing
- Connection pooling and failover

**Phase 4 - FAST Protocol (Weeks 13-16)**
- `ironfix-fast`: Stop-bit encoding/decoding
- Presence map handling
- All field operators (copy, delta, increment, tail)
- Template XML parser
- UDP multicast receiver with A/B arbitration

**Phase 5 - Code Generation (Weeks 17-20)**
- `ironfix-codegen`: Build-time Rust generation
- `ironfix-derive`: Procedural macros
- All FIX versions (4.0-5.0 SP2)
- Custom tag support

**Phase 6 - Production Hardening (Weeks 21-24)**
- `ironfix-engine`: High-level facade
- Conformance test suite
- Performance benchmarks
- Documentation and examples

This architecture is intended as a foundation for building a FIX engine in Rust that combines the correctness guarantees of the type system with the performance characteristics required for modern electronic trading. Whether it delivers those performance characteristics is currently unknown: the criterion harness is now in place, but no baseline has been recorded, so producing and publishing real measurements remains a prerequisite for any performance claim either way.