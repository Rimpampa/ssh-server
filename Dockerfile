FROM rust:latest AS builder

WORKDIR /build

COPY Cargo.toml ./
COPY build.rs ./
COPY src/  ./src/

RUN apt-get update && apt-get install -y libclang-dev

RUN cargo build --release

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

FROM ubuntu:latest

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    openssl \
    xxd \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Set bash as default shell
RUN useradd -D -s /bin/bash

# Create app directory
WORKDIR /app

# Copy the binary from builder stage (statically linked musl binary)
COPY --from=builder /build/target/release/ssh-server /app/ssh-server

# Set executable permissions
RUN chmod +x /app/ssh-server

# Expose SSH port
EXPOSE 2222

# Default command - user can override with their key path
ENTRYPOINT ["/app/ssh-server", "/app/key"]
