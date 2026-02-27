# SSH Server in Rust

A simple _unsecure_ SSH server written in Rust that spawns interactive shell sessions for any user with full PTY support.

The server is designed for working with a shared envrionment in a classroom,
when a student connects to the server for the first time a new user is created for them with the provided password.

The server disallows more than one connection to the same user at the same time by checking the peer socket (IP + port).

Only **Linux** is supported.

## Build

To build this project simply run:

``` bash
cargo build --release
```

## Docker Deployment

To build the Docker image and start the container run:

```bash
# Build image:
docker build -t ssh-server .

# Run container:
# mykey is your SSH private key
docker run -p 2222:2222 \
  -v $(pwd)/mykey:/app/key:ro \
  -e RUST_LOG=info \
  --user root \
  ssh-server
```

The container has the following programs:
- `openssl` - Cryptographic operations
- `xxd` - Hex dump utility
- `bash` - Shell for user sessions
