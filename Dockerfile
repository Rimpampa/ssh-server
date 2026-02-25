# Stage 1: Builder
FROM rust:latest AS builder

WORKDIR /build

# Install build dependencies for musl static linking
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

# Add musl target for static compilation
RUN rustup target add x86_64-unknown-linux-musl

# Copy the project files
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/

# Build the binary in release mode
RUN cargo build --release --target x86_64-unknown-linux-musl

# Stage 2: Runtime
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    openssl \
    xxd \
    bash

# Create app directory
WORKDIR /app

# Copy the binary from builder stage (statically linked musl binary)
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/ssh-server /app/ssh-server

# Set executable permissions
RUN chmod +x /app/ssh-server

# Expose SSH port
EXPOSE 2222

# Default command - user can override with their key path
ENTRYPOINT ["/app/ssh-server", "/app/key"]
