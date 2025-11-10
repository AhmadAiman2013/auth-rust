# Builder stage
FROM rust:1.90-slim-bookworm AS builder
WORKDIR /app

# Install dependencies for musl target & OpenSSL
RUN apt-get update && apt-get install -y musl-tools pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Add the ARM64 musl target
RUN rustup target add aarch64-unknown-linux-musl

# Copy source
COPY . .

# Build release binary for ARM64 musl
RUN cargo build --release --target aarch64-unknown-linux-musl

# Runtime stage (minimal)
FROM scratch
WORKDIR /app

# Copy binary
COPY --from=builder /app/target/aarch64-unknown-linux-musl/release/auth-rust .

# Expose port and define command
EXPOSE 8080
CMD ["./auth-rust"]
