## 🏗️ Builder stage
FROM rust:1.90-alpine AS builder

WORKDIR /app

# --- 🎯 FIX: Install build-base for the linker files (crti.o) ---
# 'build-base' provides gcc, make, musl-dev, and the required linker objects.
RUN apk update && apk add --no-cache build-base openssl-dev pkgconf

COPY . .

# Build release binary for ARM64 musl
# This command should now succeed as the linker dependencies are available.
RUN cargo build --release --target aarch64-unknown-linux-musl

---

## 🚀 Runtime stage (minimal)
FROM scratch
WORKDIR /app

# Copy binary
COPY --from=builder /app/target/aarch64-unknown-linux-musl/release/auth-rust .

# Expose port and define command
EXPOSE 8080
CMD ["./auth-rust"]