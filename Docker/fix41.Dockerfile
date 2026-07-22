# syntax=docker/dockerfile:1

# FIX 4.1 server image.
#
# Build from the repository root so the context includes the whole workspace:
#   docker build -f Docker/fix41.Dockerfile -t ironfix-fix41:latest .
#
# The context is trimmed by /.dockerignore. Without it `COPY . .` ships target/
# and .git/ to the daemon, which is gigabytes and invalidates every cached layer
# on any build artefact change.

# Build stage
FROM rust:1.92.0-alpine3.23 AS builder

# rust-toolchain.toml pins `channel = "stable"`, which rustup resolves to
# whatever "stable" means on the day of the build — silently overriding the
# version in the FROM line above and downloading a second toolchain mid-build.
# RUSTUP_TOOLCHAIN takes precedence over the file and keeps the image
# reproducible.
ENV RUSTUP_TOOLCHAIN=1.92.0

RUN apk add --no-cache musl-dev

WORKDIR /app

COPY . .

# Cache mounts carry the registry and the build directory across builds. They
# are not part of the image, so the binary is copied out inside the same RUN.
# `--locked` fails the build rather than silently resolving a different
# dependency set than Cargo.lock records.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked --example fix41_server -p ironfix-example \
    && cp target/release/examples/fix41_server /fix41_server

# Runtime stage
FROM alpine:3.23

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /fix41_server /app/fix41_server

# The server binds FIX_HOST. It must be 0.0.0.0 for the published port to be
# reachable from outside the container; 127.0.0.1 would accept nothing.
ENV FIX_HOST=0.0.0.0
ENV FIX_PORT=9871
ENV FIX_SENDER=SERVER
ENV FIX_TARGET=CLIENT

EXPOSE 9871

CMD ["/app/fix41_server"]
