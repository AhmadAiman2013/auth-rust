## 🏗️ Builder stage
FROM rust:1.90-alpine AS builder

WORKDIR /app

# Install necessary C/build dependencies using Alpine's 'apk'
# musl-dev is included in the base image, but we need openssl-dev and pkgconf
# We use 'pkgconf' instead of 'pkg-config' on Alpine
RUN apk update && apk add --no-cache openssl-dev pkgconf

# ❌ REMOVE: The musl target is the native host target for this image,
# and often rust-alpine comes pre-configured for its host architecture.
# We will use the native toolchain that builds musl binaries.
# RUN rustup target add aarch64-unknown-linux-musl
# (This step is often not needed, or handled by the base image's configuration)

# Copy source
COPY . .

# Build release binary for ARM64 musl
# Since the Alpine base is already a musl environment, the build may not even
# need the explicit '--target aarch64-unknown-linux-musl', but we keep it
# for explicit clarity and safety.
RUN cargo build --release --target aarch64-unknown-linux-musl

## 🚀 Runtime stage (minimal)
FROM scratch
WORKDIR /app

# Copy binary
COPY --from=builder /app/target/aarch64-unknown-linux-musl/release/auth-rust .

# Expose port and define command
EXPOSE 8080
CMD ["./auth-rust"]