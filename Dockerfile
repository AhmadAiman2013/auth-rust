## 🏗️ Builder stage
FROM rust:1.90-alpine AS builder

WORKDIR /app
RUN apk update && apk add --no-cache openssl-dev pkgconf

COPY . .


RUN cargo build --release --target aarch64-unknown-linux-musl

## 🚀 Runtime stage (minimal)
FROM scratch
WORKDIR /app

# Copy binary
COPY --from=builder /app/target/aarch64-unknown-linux-musl/release/auth-rust .

# Expose port and define command
EXPOSE 8080
CMD ["./auth-rust"]