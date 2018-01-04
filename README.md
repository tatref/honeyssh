# What is this?
POC of simple SSH honeypot in Rust

# Setup

The `DockerFile` is a fork from https://github.com/clux/muslrust that allows building static rust binaries

```
docker build -t muslrust .
mkdir -p cargo_cache
rm -rf cargo_cache/*
rm -rf target
```

Generate an SSH server key (will be used by the honeypot)
```
ssh-keygen -t ed25519 -f ./id_ed25519
```

You can also generate client keys and put these under `./client_keys`, these will be accepted.

# Compilation via the muslrust container
`libsodium` and `openssl` are required, using a container is simpler
```
docker run -v $PWD:/volume -v $PWD/cargo_cache:/root/.cargo --rm -it muslrust cargo build --release
```

# Execution
```
./target/x86_64-unknown-linux-musl/release/honeyssh 127.0.0.1:2222
```

# Usage
```
ssh localhost -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
```

Any user/password combination is accepted. Any key under `./client_keys` are also accepted.

The `./dump/` directory will be populated with the raw bytes sent from the client.

# Notes on security
None
