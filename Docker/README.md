# IronFix Docker Images

Dockerfiles for building and running IronFix FIX protocol servers.

## Available Servers

| Dockerfile | FIX Version | Default Port |
|------------|-------------|--------------|
| `fix40.Dockerfile` | FIX 4.0 | 9870 |
| `fix41.Dockerfile` | FIX 4.1 | 9871 |
| `fix42.Dockerfile` | FIX 4.2 | 9872 |
| `fix43.Dockerfile` | FIX 4.3 | 9873 |
| `fix44.Dockerfile` | FIX 4.4 | 9876 |
| `fix50.Dockerfile` | FIX 5.0 (FIXT.1.1) | 9880 |
| `fix50sp1.Dockerfile` | FIX 5.0 SP1 | 9881 |
| `fix50sp2.Dockerfile` | FIX 5.0 SP2 | 9882 |
| `fast.Dockerfile` | FAST Protocol | 9890 |

## Building

Build from the repository root:

```bash
# Build FIX 4.4 server
docker build -f Docker/fix44.Dockerfile -t ironfix-fix44:latest .

# Build all servers
for v in 40 41 42 43 44 50 50sp1 50sp2; do
  docker build -f Docker/fix${v}.Dockerfile -t ironfix-fix${v}:latest .
done
```

## Running

```bash
# Run FIX 4.4 server
docker run -d -p 9876:9876 --name fix44-server ironfix-fix44:latest

# Run with custom configuration
docker run -d -p 9876:9876 \
  -e FIX_HOST=0.0.0.0 \
  -e FIX_PORT=9876 \
  -e FIX_SENDER=MY_SERVER \
  -e FIX_TARGET=MY_CLIENT \
  --name fix44-server ironfix-fix44:latest
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FIX_HOST` | Bind address | `0.0.0.0` |
| `FIX_PORT` | Listen port | Version-specific |
| `FIX_SENDER` | SenderCompID | `SERVER` |
| `FIX_TARGET` | TargetCompID | `CLIENT` |

The FAST image also honours `FAST_HOST` and `FAST_PORT`, which take precedence
over `FIX_HOST` / `FIX_PORT`. It sets both spellings to `0.0.0.0` and `9890`, so
the published port is reachable whichever a deployment uses.

## Smoke test

Confirm a running container accepts a connection on its published port. For the
FAST image:

```bash
docker build -f Docker/fast.Dockerfile -t ironfix-fast:latest .
docker run -d -p 9890:9890 --name fast-smoke ironfix-fast:latest

# Its log must show it bound 0.0.0.0, not 127.0.0.1:
docker logs fast-smoke     # "FAST server listening addr=0.0.0.0:9890"

# And an external client must decode its stream:
FAST_PORT=9890 cargo run --release --example fast_client -p ironfix-example

docker rm -f fast-smoke
```

The FIX servers are the same shape on their own ports; point the matching
`fixNN_client` at `127.0.0.1:<port>`.

## Image Details

- **Build stage**: `rust:1.92.0-alpine3.23`, toolchain pinned via
  `RUSTUP_TOOLCHAIN=1.92.0` so rustup does not resolve the repo's `stable`
  channel to a different version mid-build.
- **Runtime stage**: `alpine:3.23`
- **Binary**: Statically linked with musl libc
- **Build context**: trimmed by `/.dockerignore` (`target/`, `.git/`, `doc/`,
  `Docker/`), so `COPY . .` does not ship gigabytes to the daemon. A BuildKit
  cache mount carries the cargo registry and `target/` across builds.

> BuildKit is required for the cache mounts (`# syntax=docker/dockerfile:1`).
> It is the default in current Docker; if yours predates that, prefix the build
> with `DOCKER_BUILDKIT=1`.
