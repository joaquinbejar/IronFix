[![Dual License](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
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
crates: the wire layer, the session layer, and a client-side engine.

## Overview

IronFix implements FIX tag=value messaging and the FAST encoding primitives from
the ground up — there is no upstream protocol library underneath it. The
tag=value decoder is zero-copy and dictionary-free: it scans bytes and hands out
field slices that borrow the input buffer, with schema validation available as a
separate, opt-in pass.

**What works today**, end to end:

- **Decoding and encoding** FIX tag=value messages, including `BodyLength` (tag
  9) and `CheckSum` (tag 10) handling and length-prefixed Length/Data field
  pairs. Every malformed-input path is a typed error, never a panic.
- **Framing** over a Tokio codec (`FixCodec`) with a bounded read buffer and an
  unconditionally verified trailer.
- **A client-side session** (`Initiator`): TCP dial, Logon handshake,
  heartbeats and TestRequests, CompID validation, sequence-gap detection,
  `ResendRequest` / `SequenceReset` / gap fill, `PossDupFlag` and
  `OrigSendingTime` handling, `ResetSeqNumFlag`, session-level `Reject`, and
  `FIXT.1.1` BeginString with `ApplVerID` for FIX 5.0 sessions.
- **A typestate session FSM** and checked sequence arithmetic in
  `ironfix-session`.
- **A QuickFIX XML dictionary loader** and a `Validator` in
  `ironfix-dictionary`.
- **FAST primitives** in `ironfix-fast`: stop-bit integers and strings, presence
  maps, and the copy/delta/increment/tail/default operators, all round-trip
  tested.

## What is not implemented yet

This list is deliberately explicit. If a capability is not named under "What
works today" and appears below, it does not exist in the code — do not plan
around it.

- **No Acceptor.** `ironfix-engine` has `Initiator` only. The server-side
  examples hand-roll their own accept loop with `Decoder` / `Encoder` directly.
- **`EngineBuilder` has no terminal method.** It collects sessions and timeouts
  but there is no `build()`; the working entry point is
  `Initiator::new(config, app).connect(addr)`.
- **The engine never uses `MessageStore`.** Resend-from-store is not wired up —
  an inbound `ResendRequest` is answered with a gap fill, not with the original
  messages. `MemoryStore` is the only store implementation; there is no
  `FileStore` and no memory-mapped store.
- **No TLS.** `ironfix-transport` contains `FixCodec` and nothing else — no TCP
  connector, no acceptor, no `rustls`. `Initiator` calls `TcpStream::connect`
  directly.
- **Async only.** Everything that touches a socket runs on Tokio. There is no
  synchronous mode, no kernel-bypass path, and no busy-polling transport.
- **Only FIX 4.4 has an embedded dictionary** (`ironfix-dictionary/spec/FIX44.xml`,
  vendored from QuickFIX). Other versions require
  `Dictionary::from_quickfix_xml` with your own XML. The `Validator` is *not*
  invoked by the engine or the codec; you call it yourself.
- **The derive macros are stubs.** `#[derive(FixMessage)]` and
  `#[derive(FixField)]` both expand to `todo!()`. Neither `ironfix-derive` nor
  `ironfix-codegen` has an in-workspace consumer.
- **FAST is standalone.** There is no FAST template XML parser, no UDP multicast
  receiver, and no wiring into the session or engine path.
- **No benchmark harness.** There is no `benches/` directory and no `criterion`
  dependency, so no latency or throughput figure in this repository has been
  measured. The `make bench*` targets currently measure nothing.

## FIX version support

The session layer is version-parameterised by `BeginString`, and there is a
runnable client/server example pair for each version below. "Dictionary" means a
dictionary is embedded in the crate and loadable without extra files.

| Version | BeginString | Example pair | Dictionary embedded |
|---------|-------------|--------------|---------------------|
| FIX 4.0 | `FIX.4.0` | yes | no |
| FIX 4.1 | `FIX.4.1` | yes | no |
| FIX 4.2 | `FIX.4.2` | yes | no |
| FIX 4.3 | `FIX.4.3` | yes | no |
| FIX 4.4 | `FIX.4.4` | yes | **yes** |
| FIX 5.0 | `FIXT.1.1` | yes | no |
| FIX 5.0 SP1 | `FIXT.1.1` | yes | no |
| FIX 5.0 SP2 | `FIXT.1.1` | yes | no |

## Crate Organization

| Crate | Description |
|-------|-------------|
| `ironfix-core` | Fundamental types, traits, and error definitions; depends on no other IronFix crate |
| `ironfix-dictionary` | QuickFIX XML loading, schema types, and the opt-in `Validator` |
| `ironfix-tagvalue` | Zero-copy tag=value decoding and encoding; dictionary-free |
| `ironfix-session` | Session-layer protocol logic: typestate FSM, sequences, heartbeats. No I/O |
| `ironfix-store` | The `MessageStore` trait and `MemoryStore` |
| `ironfix-transport` | `FixCodec`, a Tokio codec that frames FIX messages. No TCP helpers, no TLS |
| `ironfix-fast` | FAST encoding/decoding primitives: stop-bit, presence maps, operators |
| `ironfix-codegen` | Build-time Rust generation from a `Dictionary` (no in-workspace consumer) |
| `ironfix-derive` | Procedural macros — currently stubs that expand to `todo!()` |
| `ironfix-engine` | The composition root: `Initiator`, `Connection`, the `Application` trait |
| `ironfix-example` | Umbrella facade (`prelude`) plus the runnable examples |

There is no `ironfix` facade crate. The umbrella re-exports live in
`ironfix-example`.

## Quick Start

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
    let config = SessionConfig::new(
        CompId::new("SENDER")?,
        CompId::new("TARGET")?,
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

See `ironfix-example/examples/fix44_engine_client.rs` for the same flow with a
real `Application` implementation.

## 🛠 Makefile Commands

This project includes a `Makefile` with common tasks to simplify development.
Here's a list of useful commands:

### 🔧 Build & Run

```sh
make build         # Compile the project
make release       # Build in release mode
make run           # Run the main binary
```

### 🧪 Test & Quality

```sh
make test          # Run all tests
make fmt           # Format code
make fmt-check     # Check formatting without applying
make lint          # Run clippy with warnings as errors
make lint-fix      # Auto-fix lint issues
make fix           # Auto-fix Rust compiler suggestions
make check         # Run fmt-check + lint + test
make pre-push      # Run fix + fmt + lint-fix + test + readme + doc (recommended before pushing)
```

### 📦 Packaging & Docs

```sh
make doc           # Check for missing docs via clippy
make doc-open      # Build and open Rust documentation
make create-doc    # Generate internal docs
make publish       # Prepare and publish a crate to crates.io
make publish-all   # Publish all crates in dependency order
```

`make readme` exists but is a no-op on this workspace — `cargo-readme` does not
apply to a multi-crate workspace, so `README.md` is maintained by hand. Edit it
directly when the public surface changes.

### 📈 Coverage & Benchmarks

```sh
make coverage            # Generate code coverage report (XML)
make coverage-html       # Generate HTML coverage report
make open-coverage       # Open HTML report
```

The `make bench*` targets are defined but there is no `benches/` directory and
no `criterion` dependency in the workspace, so they currently measure nothing.

### 🧪 Git & Workflow Helpers

```sh
make git-log             # Show commits on current branch vs main
make zip                 # Create zip without target/ and temp files
make tree                # Visualize project tree (excludes common clutter)
```

`make check-spanish` is defined but currently broken — it invokes a `scripts/`
directory that is not present in the repository. The English-only rule for code,
comments and commit messages still applies; it is simply not machine-enforced.

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

Per-version pairs — note that the servers hand-roll their accept loop and
session handling, because there is no `Acceptor` in `ironfix-engine`:

- `fix40_server` / `fix40_client` — FIX 4.0 (port 9870)
- `fix41_server` / `fix41_client` — FIX 4.1 (port 9871)
- `fix42_server` / `fix42_client` — FIX 4.2 (port 9872)
- `fix43_server` / `fix43_client` — FIX 4.3 (port 9873)
- `fix44_server` / `fix44_client` — FIX 4.4 (port 9876)
- `fix50_server` / `fix50_client` — FIX 5.0 over FIXT.1.1 (port 9880)
- `fix50sp1_server` / `fix50sp1_client` — FIX 5.0 SP1 (port 9881)
- `fix50sp2_server` / `fix50sp2_client` — FIX 5.0 SP2 (port 9882)

Engine and concurrency examples:

- `fix44_engine_client` — the same client flow driven by `Initiator`, which owns
  the socket, framing, Logon and heartbeats. Pairs with `fix44_server`.
- `fix44_server_channel` — server-side message hand-off over a channel.

FAST examples:

- `fast_server` / `fast_client` — FAST encode/decode over a socket
- `fast_server_spsc` — FAST server with single-producer/single-consumer hand-off

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

**License**: MIT
