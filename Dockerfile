## Builder stage
FROM rust:1.95-alpine AS builder

WORKDIR /app

# 'build-base' provides gcc, make, musl-dev, and linker objects.
# 'openssl-dev' should contain the static libs on musl.
RUN apk update && apk add --no-cache build-base openssl-dev pkgconf

# Alpine installs OpenSSL headers under /usr/include/openssl
# and the libraries under /usr/lib
ENV OPENSSL_INCLUDE_DIR=/usr/include/
ENV OPENSSL_LIB_DIR=/usr/lib/

# Set PKG_CONFIG_ALLOW_CROSS=1 just in case, though in this native musl image, it might not be strictly needed.
ENV PKG_CONFIG_ALLOW_CROSS=1

# Copy source
COPY . .

# Build release binary for ARM64 musl
# This command remains clean, relying on the environment variables above.
RUN cargo build --release --target aarch64-unknown-linux-musl

## Runtime stage
FROM scratch
WORKDIR /app

# Copy binary
COPY --from=builder /app/target/aarch64-unknown-linux-musl/release/auth-rust .

# Expose port and define command
EXPOSE 8080
CMD ["./auth-rust"]