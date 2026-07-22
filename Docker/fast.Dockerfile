# syntax=docker/dockerfile:1

# FAST market data server image.
#
# Build from the repository root so the context includes the whole workspace:
#   docker build -f Docker/fast.Dockerfile -t ironfix-fast:latest .
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
    cargo build --release --example fast_server -p ironfix-example \
    && cp target/release/examples/fast_server /fast_server

# Runtime stage
FROM alpine:3.23

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /fast_server /app/fast_server

# The server binds FIX_HOST. It must be 0.0.0.0 for the published port to be
# reachable from outside the container; 127.0.0.1 would accept nothing.
ENV FIX_HOST=0.0.0.0
ENV FIX_PORT=9890
# FAST_HOST / FAST_PORT are honoured too and take precedence, so an
# existing deployment using either spelling keeps working. The image
# previously set only FAST_HOST, which nothing read: the server bound
# 127.0.0.1 and the published port accepted no connection.
ENV FAST_HOST=0.0.0.0
ENV FAST_PORT=9890

EXPOSE 9890

CMD ["/app/fast_server"]
