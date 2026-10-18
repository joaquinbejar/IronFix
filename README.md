[![License](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![Crates.io](https://img.shields.io/crates/v/ironfix-core.svg)](https://crates.io/crates/ironfix-core)
[![Downloads](https://img.shields.io/crates/d/ironfix-core.svg)](https://crates.io/crates/ironfix-core)
[![Stars](https://img.shields.io/github/stars/joaquinbejar/IronFix.svg)](https://github.com/joaquinbejar/IronFix/stargazers)
[![Issues](https://img.shields.io/github/issues/joaquinbejar/IronFix.svg)](https://github.com/joaquinbejar/IronFix/issues)
[![PRs](https://img.shields.io/github/issues-pr/joaquinbejar/IronFix.svg)](https://github.com/joaquinbejar/IronFix/pulls)

[![Build](https://img.shields.io/github/actions/workflow/status/joaquinbejar/IronFix/build.yml?branch=main&label=build)](https://github.com/joaquinbejar/IronFix/actions/workflows/build.yml)
[![Tests](https://img.shields.io/github/actions/workflow/status/joaquinbejar/IronFix/tests.yml?branch=main&label=tests)](https://github.com/joaquinbejar/IronFix/actions/workflows/tests.yml)
[![Coverage](https://img.shields.io/codecov/c/github/joaquinbejar/IronFix)](https://codecov.io/gh/joaquinbejar/IronFix)
[![Dependencies](https://img.shields.io/librariesio/github/joaquinbejar/IronFix)](https://libraries.io/github/joaquinbejar/IronFix)
[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg)](https://docs.rs/ironfix-engine)

# IronFix

A FIX/FAST protocol engine for Rust, built as a Cargo workspace of focused
crates: the wire layer, the session layer, and a client and server engine.

## Overview

IronFix implements FIX tag=value messaging and the FAST encoding primitives from
the ground up — there is no upstream protocol library underneath it. The
tag=value decoder is zero-copy and dictionary-free: it scans bytes and hands out
field slices that borrow the input buffer, with schema validation available as a
separate, opt-in pass.

**Scope.** IronFix covers the FIX tag=value layer (FIX 4.0 to FIX 5.0 SP2 over
FIXT.1.1) and FAST. A binary order-entry stack, SOFH framing and a FIXP session
over SBE (via `ironsbe-core`), is planned inside the workspace
(`doc/adr/0003-fixp-sofh-in-workspace.md`, tracked in #94 to #97); none of it
exists yet.

**What works today**, end to end:

- **Decoding and encoding** FIX tag=value messages, including `BodyLength` (tag
  9) and `CheckSum` (tag 10) handling and length-prefixed Length/Data field
  pairs. Every malformed-input path is a typed error, never a panic.
- **Framing** over a Tokio codec (`FixCodec`) with a bounded read buffer and an
  unconditionally verified trailer. Both engines skip garbled inbound frames (a
  bad `CheckSum` or `BodyLength`, bytes before `8=`, `MsgType` not third) as
  FIX requires, in session and during the Logon handshake: the frame consumes
  no `MsgSeqNum`, is not counted as proof of life, and its gap is recovered by
  `ResendRequest`. An optional `garbled_frame_limit` logs out a link that keeps
  garbling. A frame above `max_message_size` still closes the session, after a
  Logout saying "message too large".
- **A client engine and a server engine** in `ironfix-engine`. `Initiator`
  dials over TCP and runs the initiator half of the Logon handshake. `Acceptor`
  serves inbound connections for one configured counterparty and runs the
  acceptor half: CompID authentication, a logon timeout, honouring the
  counterparty's `HeartBtInt`, and mirroring `ResetSeqNumFlag`.
  `EngineBuilder` terminates in either one via `into_initiator()` /
  `into_acceptor()`.
- **One session reactor shared by both roles.** Once Logon completes, the
  engine owns the socket: heartbeats and TestRequests at the negotiated
  interval, CompID and `SendingTime` validation, sequence-gap detection with
  bounded `ResendRequest` recovery, `SequenceReset` / gap fill, `PossDupFlag`
  and `OrigSendingTime` handling, session-level `Reject`, a socket write
  timeout, the Logout handshake, and `FIXT.1.1` BeginString with `ApplVerID`
  for FIX 5.0 sessions. `HeartBtInt = 0` disables heartbeating (ask for it
  with `SessionConfigBuilder::disable_heartbeats`), and any inbound message
  clears a pending TestRequest.
- **Resend from store** in both roles. Attach a `MessageStore` with
  `Initiator::with_store`, `Acceptor::with_store` or `EngineBuilder::with_store`
  and an inbound `ResendRequest` replays the stored application messages with
  `PossDupFlag = Y` and the original `SendingTime` in `OrigSendingTime`;
  administrative messages, and anything the store cannot produce, are covered
  by gap fill. A session starts from the store's counters unless it resets the
  sequence. Store writes are fallible and ordered: a frame is filed and the
  next sender number persisted before its bytes are written, and the next
  target number is persisted before an inbound message is acted on.
  `with_store_failure_policy` chooses between warning and continuing (the
  default, which gives no crash guarantee) or failing closed, writing nothing
  the store has not accepted. Every store call is bounded by
  `with_store_timeout`. A store belongs to exactly one engine. The acceptor
  touches its store only once the peer is authenticated (`from_admin` accepted
  it), and resets it only for a Logon that passes every check, so a refused
  `ResetSeqNumFlag` Logon cannot clear it. With a store attached, a Logon
  refused before authentication (wrong version, encryption, CompIDs, clock or
  credentials) gets no reply; a second Logon for a session already live gets
  no reply in every case; an authenticated peer refused after that
  (`HeartBtInt`, `MsgSeqNum`) gets a filed Logout saying why.
- **A typestate session FSM** and checked sequence arithmetic in
  `ironfix-session`.
- **A QuickFIX XML dictionary loader** and a `Validator` in
  `ironfix-dictionary`, with four QuickFIX dictionaries embedded verbatim:
  FIX 4.2 (`Dictionary::fix42()`), FIX 4.4 (`Dictionary::fix44()`), the
  FIXT 1.1 transport dictionary (`Dictionary::fixt11()`) and the FIX 5.0 SP2
  application dictionary (`Dictionary::fix50sp2()`). `SessionDictionary`
  composes FIXT 1.1 with an application dictionary of any version FIXT 1.1
  carries (FIX 4.0 through 5.0 SP2), and `Validator::for_session` validates
  against the pair with QuickFIX-like semantics: `BeginString` must be
  `FIXT.1.1`, header and trailer come from the transport, the body from the
  application, and admin messages entirely from the transport.
- **A zero-copy repeating-group reader** in `ironfix-dictionary`. Build a
  `MessageLayout` once per message type from a dictionary (or describe the
  groups at compile time with `GroupSpec` / `GroupSet`), then read a decoded
  message's groups as borrowed views: `layout.read(&msg, 453)` checks the
  whole group with the validator's own walk and yields one `GroupEntry` per
  entry, with own-level field lookup and nested groups. A malformed group is
  a typed `GroupError`, never a partial view. A successful read (iteration
  and field lookup included) and a read that fails with a structural error
  allocate nothing, for groups of up to 512 entry-level members (every group
  of the embedded dictionaries); a wider group allocates one small buffer per
  walk, and errors that carry strings (`MsgTypeMismatch`) allocate them. The
  allocation-free paths are proved with a counting allocator in
  `ironfix-dictionary/tests/group_reader_allocations.rs`. It is opt-in: the
  engine does not call it.
- **Code generation.** `#[derive(FixMessage)]` and `#[derive(FixField)]` in
  `ironfix-derive` implement the `ironfix-core` traits with typed
  `DecodeError` / `EncodeError` paths (compile-tested in
  `ironfix-derive/tests/`), and `ironfix-codegen` emits Rust from a loaded
  `Dictionary` (a golden sample and the full FIX 4.2 and FIXT 1.1 outputs are
  compile-tested in `ironfix-codegen/tests/`).
- **FAST primitives** in `ironfix-fast`: stop-bit encode/decode of unsigned
  and signed integers, ASCII strings and byte vectors, each in nullable and
  non-nullable form, plus presence maps, all round-trip tested. The `Operator`
  table and `Operator::transfer` (which decides, from the operator, the field's
  optionality and the presence map, where a field's value comes from) are
  implemented; *applying* an operator to produce a value is not.

## What is not implemented yet

This list is deliberately explicit. If a capability is not named under "What
works today" and appears below, it does not exist in the code — do not plan
around it.

- **No persistent store.** `MemoryStore` is the only `MessageStore`; there is
  no `FileStore` and no memory-mapped store, so stored messages and sequence
  numbers do not survive a restart (`ironfix-store/src/lib.rs`). Inbound
  application messages are delivered at most once: a crash, or a session
  close whose application queue does not drain in time, loses the messages
  still queued. The close logs the lost range; nothing reports a loss across
  a restart yet (#105). Inbound frames are not filed.
- **One session per engine.** `EngineBuilder` takes exactly one
  `SessionConfig`; `into_initiator()` and `into_acceptor()` return
  `EngineError::Configuration` for zero or several
  (`ironfix-engine/src/builder.rs`).
- **No TLS.** There is no `rustls` dependency anywhere. `ironfix-transport`
  contains `FixCodec` only; the engines open plain TCP themselves (`Initiator`
  calls `TcpStream::connect`, `Acceptor` serves a `TcpStream`). See "Current
  limitations" in `ironfix-engine/src/lib.rs`.
- **Async only.** Everything that touches a socket runs on Tokio. There is no
  synchronous mode, no kernel-bypass path, and no busy-polling transport. A
  sans-IO session core with Tokio as one driver is the accepted direction
  (`doc/adr/0002-session-driver.md`, tracked in #90 to #93); none of it exists
  yet.
- **Only four dictionaries are embedded**: FIX 4.2, FIX 4.4, FIXT 1.1 and
  FIX 5.0 SP2 (`ironfix-dictionary/spec/`, vendored verbatim from QuickFIX).
  FIX 4.0, 4.1, 4.3, 5.0 and 5.0 SP1 require
  `Dictionary::from_quickfix_xml` with your own XML
  (`ironfix-dictionary/src/loader.rs`). `SessionDictionary` does not read
  `ApplVerID(1128)`: you choose the application dictionary when you build it.
  `Validator::new` does not check `BeginString`; only `Validator::for_session`
  does. The `Validator` is *not* invoked by the engine or the codec; you call
  it yourself (`ironfix-engine/src/lib.rs`).
- **The embedded FIXT 1.1 dictionary deviates from FIXT 1.1 on Logon.** The
  vendored QuickFIX `FIXT11.xml` defines the `MsgTypeGrp` component with no
  members and does not define `NoMsgTypes(384)` or `MsgDirection(385)`, so a
  Logon carrying the `NoMsgTypes` group is reported as invalid. The file is
  kept verbatim; to accept the group, load a FIXT 1.1 dictionary that defines
  it with `Dictionary::from_quickfix_xml` and compose that
  (`ironfix-dictionary/spec/README.md`).
- **Generated code has no consumer.** Nothing in the workspace uses the
  derives or `ironfix-codegen` output, so field access on the session path is
  untyped tag lookup (`ironfix-codegen/src/lib.rs`).
- **FAST has no template layer.** There is no FAST template XML parser, no
  operator application (copy, delta, increment, tail), no decimal codec and no
  sequence decoding, so `ironfix-fast` decodes the fields of a message only when
  something else supplies their order. There is also no UDP multicast receiver
  and no wiring into the session or engine path (`ironfix-fast/src/lib.rs`).
- **No recorded benchmark baseline.** A criterion harness now exists (see
  Benchmarks below): `ironfix-tagvalue`, `ironfix-fast` and `ironfix-transport`
  each carry a `benches/` target run by `make bench`. It ships no saved baseline
  and no published figures, so every latency and throughput target in `doc/`
  remains a design goal, unmeasured until you run it on hardware you name.

## FIX version support

The session layer is version-parameterised by `BeginString`, and there is a
runnable client/server example pair for each version below. "Dictionary
embedded" means a dictionary is embedded in `ironfix-dictionary` and loadable
without extra files. The FIX 5.0 family runs over a FIXT 1.1 session, so it
needs two dictionaries: the FIXT 1.1 transport dictionary (`Dictionary::fixt11()`,
embedded) and the application dictionary for the version, composed with
`SessionDictionary`. The same composition accepts a FIX 4.x application
dictionary, for a counterparty that carries FIX 4.x messages over FIXT 1.1
(ApplVerID 2 to 6).

| Version | BeginString | Example pair | Dictionary embedded |
|---------|-------------|--------------|---------------------|
| FIX 4.0 | `FIX.4.0` | yes | no |
| FIX 4.1 | `FIX.4.1` | yes | no |
| FIX 4.2 | `FIX.4.2` | yes | **yes** (`Dictionary::fix42()`) |
| FIX 4.3 | `FIX.4.3` | yes | no |
| FIX 4.4 | `FIX.4.4` | yes | **yes** (`Dictionary::fix44()`) |
| FIX 5.0 | `FIXT.1.1` | yes | transport only (FIXT 1.1); application no |
| FIX 5.0 SP1 | `FIXT.1.1` | yes | transport only (FIXT 1.1); application no |
| FIX 5.0 SP2 | `FIXT.1.1` | yes | **yes** (`Dictionary::fixt11()` + `Dictionary::fix50sp2()`) |

The embedded dictionaries are the QuickFIX data dictionaries, redistributed
under the QuickFIX Software License, Version 1.0
(`ironfix-dictionary/spec/LICENSE-QUICKFIX`; provenance and checksums in
`ironfix-dictionary/spec/README.md`). This product includes software developed
by quickfixengine.org (<http://www.quickfixengine.org/>).

## Crate Organization

| Crate | Description |
|-------|-------------|
| `ironfix-core` | Fundamental types, traits, and error definitions; depends on no other IronFix crate |
| `ironfix-dictionary` | QuickFIX XML loading, schema types, and the opt-in `Validator` |
| `ironfix-tagvalue` | Zero-copy tag=value decoding and encoding; dictionary-free |
| `ironfix-session` | Session-layer protocol logic: typestate FSM, sequences, heartbeats. No I/O |
| `ironfix-store` | The `MessageStore` trait and `MemoryStore` |
| `ironfix-transport` | `FixCodec`, a Tokio codec that frames FIX messages. No TCP helpers, no TLS |
| `ironfix-fast` | FAST encoding/decoding primitives: stop-bit, presence maps, the operator table. No template layer |
| `ironfix-codegen` | Build-time Rust generation from a `Dictionary` (no in-workspace consumer) |
| `ironfix-derive` | `#[derive(FixMessage)]` / `#[derive(FixField)]` for the `ironfix-core` traits (no in-workspace consumer) |
| `ironfix-engine` | The composition root: `Initiator`, `Acceptor`, `EngineBuilder`, `Connection`, the `Application` trait |
| `ironfix-example` | Umbrella facade (`prelude`) plus the runnable examples |

There is no `ironfix` facade crate. The umbrella re-exports live in
`ironfix-example`.

## Installation

Each crate is published separately on crates.io. For the engine:

```toml
[dependencies]
ironfix-core = "0.4"
ironfix-engine = "0.4"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
```

## Quick Start

### Client

Connect as an initiator, send a `NewOrderSingle`, then log out. The engine owns
the socket: it dials, frames, performs the Logon handshake, and stamps the
header, `MsgSeqNum` and trailer on everything you send.

```rust,no_run
use std::sync::Arc;
use std::time::Duration;

use ironfix_engine::{Initiator, NoOpApplication, OutboundMessage};
use ironfix_engine::SessionConfig;
use ironfix_core::MsgType;
use ironfix_core::types::CompId;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Sender is this client; target is the venue (the server below).
    let config = SessionConfig::new(
        CompId::new("CLIENT")?,
        CompId::new("VENUE")?,
        "FIX.4.4",
    )
    .with_heartbeat_interval(Duration::from_secs(30));

    // Replace NoOpApplication with your own `Application` impl to receive
    // on_logon / from_app / from_admin callbacks.
    let initiator = Initiator::new(config, Arc::new(NoOpApplication))
        .with_connect_timeout(Duration::from_secs(5));
    let connection = initiator.connect("127.0.0.1:9876").await?;

    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, "ORD001")
        .push_str(55, "AAPL")
        .push_char(54, '1')
        .push_uint(38, 100)
        .push_str(44, "150.50")
        .push_char(40, '2');
    connection.send(order).await?;

    connection.logout().await?;
    connection.wait_closed().await;
    Ok(())
}
```

### Server

`EngineBuilder` terminates in either engine: `into_initiator()` produces the
client above, and `into_acceptor()` produces an `Acceptor` that establishes
sessions on inbound connections. Both engines hand the socket to the same
session reactor once the Logon handshake completes.

```rust,no_run
use ironfix_core::types::CompId;
use ironfix_engine::{EngineBuilder, SessionConfig};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Sender is this venue; target is the client it expects to log on.
    let config = SessionConfig::new(
        CompId::new("VENUE")?,
        CompId::new("CLIENT")?,
        "FIX.4.4",
    );

    // Add `.with_application(your_app)` to receive the session callbacks.
    let acceptor = EngineBuilder::new()
        .add_session(config)
        .into_acceptor()?;

    let listener = TcpListener::bind("0.0.0.0:9876").await?;
    let connection = acceptor.accept(&listener).await?;
    connection.wait_closed().await;
    Ok(())
}
```

See `ironfix-example/examples/fix44_engine_client.rs` for the client flow with a
real `Application` implementation, and `fix44_server.rs` for the matching
`Acceptor`-based server that answers each `NewOrderSingle` with an
`ExecutionReport`.


## 🛠 Makefile Commands

This project includes a `Makefile` with common tasks to simplify development.
Here's a list of useful commands:

### 🔧 Build & Run

```sh
make build         # Compile the workspace
make release       # Build the workspace in release mode
make run EXAMPLE=fix44_server   # Run one example (the workspace has no binaries)
```

### 🧪 Test & Quality

```sh
make test          # Run all tests
make fmt           # Format code
make fmt-check     # Check formatting without applying
make lint          # Run clippy with warnings as errors
make lint-fix      # Auto-fix lint issues
make fix           # Auto-fix Rust compiler suggestions
make check         # Run fmt-check + lint + test + doc + check-spanish
make pre-push      # Run fix + fmt + lint-fix + test + check-spanish + readme + doc
```

### 📦 Packaging & Docs

```sh
make doc           # Fail on any undocumented public item (clippy -D missing_docs)
make doc-open      # Build and open Rust documentation
make create-doc    # Generate internal docs
make readme        # No-op: README.md is hand-maintained in this workspace
make publish       # Explain how to publish; see publish-all
make publish-all   # Publish all crates in dependency order, fail-fast
```

Publishing reads `CARGO_REGISTRY_TOKEN` from the environment — it is never
passed on a command line. Preview the sequence without touching crates.io with
`make publish-all DRY_RUN=1`.

### 📈 Coverage & Benchmarks

```sh
make coverage            # Generate code coverage report (XML)
make coverage-html       # Generate HTML coverage report
make open-coverage       # Open HTML report
make bench               # Run the criterion benchmarks
make bench-quick         # Reduced sample count; a smoke run, not a measurement
make bench-build         # Compile the benchmarks without running them
make bench-show          # Open the criterion HTML report
make bench-save          # Save the current run as a named baseline
make bench-compare       # Compare the current run against a saved baseline
make bench-clean         # Remove benchmark data
```

Benchmarks cover the hot paths: tag=value decode/encode and checksum
(`ironfix-tagvalue`), the FAST stop-bit and presence-map primitives
(`ironfix-fast`), and the `FixCodec` framing loop (`ironfix-transport`).

ℹ️ The harness ships **no recorded baseline and no published figures**. Every
performance number in `doc/` is a design target; treat any figure as unmeasured
until you have produced it yourself with `make bench` on hardware you name.

### 🧪 Git & Workflow Helpers

```sh
make git-log             # Show commits on current branch vs main
make check-spanish       # Enforce English-only sources and docs (runs in CI)
make zip                 # Create zip without target/ and temp files
make tree                # Visualize project tree (excludes common clutter)
```

### 🤖 GitHub Actions (via act)

```sh
make workflow-build      # Simulate build workflow
make workflow-lint       # Simulate lint workflow
make workflow-test       # Simulate test workflow
make workflow-coverage   # Simulate coverage workflow
make workflow            # Run all workflows
```

ℹ️ Requires act for local workflow simulation and cargo-tarpaulin for coverage.

## Examples

All examples live in `ironfix-example/examples/`. Each FIX version has a
client/server pair; run the server first, then the client in another terminal.

```bash
# Start a FIX 4.4 server
cargo run --example fix44_server

# In another terminal, start the client
cargo run --example fix44_client
```

Per-version pairs. Only `fix44_server` runs on the engine's `Acceptor`; the
other servers hand-roll their accept loop with a raw `Decoder` / `Encoder` and
implement no real session behaviour, so treat them as wire-format demos rather
than templates:

- `fix40_server` / `fix40_client` — FIX 4.0 (port 9870)
- `fix41_server` / `fix41_client` — FIX 4.1 (port 9871)
- `fix42_server` / `fix42_client` — FIX 4.2 (port 9872)
- `fix43_server` / `fix43_client` — FIX 4.3 (port 9873)
- `fix44_server` / `fix44_client` — FIX 4.4 (port 9876)
- `fix50_server` / `fix50_client` — FIX 5.0 over FIXT.1.1 (port 9880)
- `fix50sp1_server` / `fix50sp1_client` — FIX 5.0 SP1 (port 9881)
- `fix50sp2_server` / `fix50sp2_client` — FIX 5.0 SP2 (port 9882)

Engine and concurrency examples:

- `fix44_engine_client`: the client flow driven by `Initiator`, which owns the
  socket, framing, Logon and heartbeats. Pairs with `fix44_server`.
- `fix44_server_channel`: per-connection reader tasks hand decoded messages to
  a single processor task over an mpsc channel, keeping business logic off the
  read path.

FAST examples:

- `fast_server` / `fast_client`: FAST encode/decode over a socket (port 9890)
- `fast_server_lockfree`: a generator thread and an encoding broadcaster
  thread joined by a bounded lock-free `crossbeam-channel`, both outside the
  Tokio runtime

## Docker

`Docker/` holds a Dockerfile per example server (the eight FIX versions plus
FAST), each a static musl build on Alpine. Build and run commands are in
`Docker/README.md`; CI builds the images through `docker.yml` when they or the
examples change.

## Documentation

- `doc/fix_operations.md` — the FIX operations specification this engine
  conforms to, plus the implementation checklist. This is the authority for
  message layouts, required tags and session semantics.
- `doc/architecture.md` — a **forward-looking design target**, not a description
  of the current code. Read its status banner before relying on anything in it.

## Contribution and Contact

We welcome contributions to this project! If you would like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and ensure that the project still builds and all tests pass.
4. Commit your changes and push your branch to your forked repository.
5. Submit a pull request to the main repository.

If you have any questions, issues, or would like to provide feedback, please feel free to contact the project
maintainer:

### **Contact Information**
- **Author**: Joaquín Béjar García
- **Email**: jb@taunais.com
- **Telegram**: [@joaquin_bejar](https://t.me/joaquin_bejar)
- **Repository**: <https://github.com/joaquinbejar/IronFix>
- **Documentation**: <https://docs.rs/ironfix-engine>

We appreciate your interest and look forward to your contributions!

**License**: MIT. The QuickFIX data dictionaries vendored in
`ironfix-dictionary/spec/` remain under the QuickFIX Software License,
Version 1.0 (`ironfix-dictionary/spec/LICENSE-QUICKFIX`).

<!-- related-projects:start -->
## Related projects

Repositories by the same author that this project depends on, and repositories that depend on it.

### Used by

| Repository | Description |
|------------|-------------|
| [fauxchange](https://github.com/joaquinbejar/fauxchange) | Exchange-in-a-box: local options exchange simulator with realistic matching, FIX/WS/REST APIs and historical replay. |
| [otc-rfq](https://github.com/joaquinbejar/otc-rfq) | OTC Request-for-Quote engine with REST, SBE streaming and FIX/WebSocket/gRPC venue connectivity. |

<!-- related-projects:end -->
