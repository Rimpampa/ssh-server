FROM rust:latest AS builder

WORKDIR /build

COPY Cargo.toml ./
COPY src/ ./src/
COPY crypt-sys/ ./crypt-sys/
COPY pam-sys/ ./pam-sys/
COPY ssh-user/ ./ssh-user/

# Install build dependencies: libcrypt-dev for crypt bindings, libpam0g-dev for PAM
RUN apt-get update && apt-get install -y \
    libcrypt-dev \
    libpam0g-dev \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

FROM ubuntu:latest

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    openssl \
    xxd \
    bash \
    libpam0g \
    libpam-runtime \
    && rm -rf /var/lib/apt/lists/*

# Provide a minimal /etc/pam.d/ssh-server that delegates to the standard
# PAM stack (pam_unix for auth, pam_limits for resource limits, etc.)
RUN echo '#%PAM-1.0'                             >> /etc/pam.d/ssh-server && \
    echo 'auth     include  system-remote-login' >> /etc/pam.d/ssh-server && \
    echo 'account  include  system-remote-login' >> /etc/pam.d/ssh-server && \
    echo 'password include  system-remote-login' >> /etc/pam.d/ssh-server && \
    echo 'session  include  system-remote-login' >> /etc/pam.d/ssh-server

# Security: Configure per-user resource limits to prevent fork bombs
# Limits apply to all users EXCEPT root (which runs the SSH server)
# Each SSH user connecting will be limited individually
# - number of processes 64 (hard 128)
# - number of open files 128 (hard 256)
# - cpu time 5mins (hard 10mins)
RUN echo "* soft  nproc   64"  >> /etc/security/limits.conf && \
    echo "* hard  nproc   128" >> /etc/security/limits.conf && \
    echo "* soft  nofile  128" >> /etc/security/limits.conf && \
    echo "* hard  nofile  256" >> /etc/security/limits.conf && \
    echo "* soft  cpu     1"   >> /etc/security/limits.conf && \
    echo "* hard  cpu     5"   >> /etc/security/limits.conf

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
