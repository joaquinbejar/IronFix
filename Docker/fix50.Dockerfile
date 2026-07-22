# syntax=docker/dockerfile:1

# FIX 5.0 (FIXT.1.1 transport) server image.
#
# Build from the repository root so the context includes the whole workspace:
#   docker build -f Docker/fix50.Dockerfile -t ironfix-fix50:latest .
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
# Cargo.lock is not committed (it is git-ignored for this workspace), so the
# build resolves dependencies fresh rather than passing `--locked` against a
# lock file the build context does not carry.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --example fix50_server -p ironfix-example \
    && cp target/release/examples/fix50_server /fix50_server

# Runtime stage
FROM alpine:3.23

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /fix50_server /app/fix50_server

# The server binds FIX_HOST. It must be 0.0.0.0 for the published port to be
# reachable from outside the container; 127.0.0.1 would accept nothing.
ENV FIX_HOST=0.0.0.0
ENV FIX_PORT=9880
ENV FIX_SENDER=SERVER
ENV FIX_TARGET=CLIENT

EXPOSE 9880

CMD ["/app/fix50_server"]
