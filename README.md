# SSH Server in Rust

A simple SSH server written in Rust that spawns interactive shell sessions for any user with full PTY support.

The server is designed for working with a shared envrionment in a classroom, when a student connects the server
creates a new user for them and allows only their host (by IP) to use that username.

Only **Linux** is supported.

## Build

To build this project simply run:

``` bash
cargo build --release
```

## Docker Deployment

The `Dockerfile` uses a two-stage build process for optimization:
- Stage 1: Builder (`rust:latest`)
  - Full Rust toolchain
  - Compiles the project in release mode
  - ~2GB image size (discarded after build)
- Stage 2: Runtime (`ubuntu:latest`)
  - Minimal Ubuntu Linux base
  - Runtime dependencies only:
    - `openssl` - Cryptographic operations
    - `xxd` - Hex dump utility
    - `bash` - Shell for user sessions
  - **Final size**: ~100-150MB

To build the Docker image and start the container run:

```bash
# Build image
docker build -t ssh-server .

# Run container
docker run -p 2222:2222 \
  -v $(pwd)/.key:/app/key:ro \
  -e RUST_LOG=info \
  --user root \
  ssh-server
# Where .key is your SSH private key
```
