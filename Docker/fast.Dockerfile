# Build stage
FROM rust:1.92.0-alpine3.23 AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app

COPY . .

RUN cargo build --release --example fast_server -p ironfix-example

# Runtime stage
FROM alpine:3.23

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/target/release/examples/fast_server /app/fast_server

# fast_server reads its bind address from FIX_HOST (via ExampleConfig) and only
# its port from FAST_PORT. FAST_HOST was never read by anything, so the server
# fell back to 127.0.0.1 and the exposed port was unreachable from outside the
# container.
ENV FIX_HOST=0.0.0.0
ENV FAST_PORT=9890

EXPOSE 9890

CMD ["/app/fast_server"]
