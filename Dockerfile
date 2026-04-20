FROM rust:1.95-alpine AS builder

WORKDIR /app

RUN apk update && apk add --no-cache build-base openssl-dev pkgconf

ENV OPENSSL_INCLUDE_DIR=/usr/include/
ENV OPENSSL_LIB_DIR=/usr/lib/
ENV PKG_CONFIG_ALLOW_CROSS=1

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release --target aarch64-unknown-linux-musl \
    && rm -f target/aarch64-unknown-linux-musl/release/deps/auth_rust*

COPY src ./src
RUN cargo build --release --target aarch64-unknown-linux-musl

FROM scratch
WORKDIR /app
COPY --from=builder /app/target/aarch64-unknown-linux-musl/release/auth-rust .
EXPOSE 8080
CMD ["./auth-rust"]