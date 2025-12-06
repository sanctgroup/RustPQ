# RustPQ

A pure Rust post-quantum cryptography suite by [Sanct](https://github.com/sanctgroup).

[![Crates.io](https://img.shields.io/crates/v/rustpq.svg)](https://crates.io/crates/rustpq)
[![Documentation](https://docs.rs/rustpq/badge.svg)](https://docs.rs/rustpq)
[![License](https://img.shields.io/crates/l/rustpq.svg)](LICENSE-MIT)

## Algorithms

| Algorithm | Standard | Status |
|-----------|----------|--------|
| ML-KEM (Kyber) | FIPS 203 | ✅ Implemented |
| ML-DSA (Dilithium) | FIPS 204 | 🚧 Coming soon |
| SLH-DSA (SPHINCS+) | FIPS 205 | 📋 Planned |

## Features

- **Pure Rust** - No unsafe code, memory-safe by design
- **`no_std` Compatible** - Works on embedded devices and bare-metal
- **Constant-time** - Resistant to timing attacks via the `subtle` crate
- **Lightweight** - Minimal dependencies

## Installation

```toml
[dependencies]
rustpq = "0.1"
```

## Usage

### ML-KEM Key Encapsulation

```rust
use rustpq::ml_kem::mlkem768::{generate, encapsulate, decapsulate};
use rand::rngs::OsRng;

// Generate a keypair
let (public_key, secret_key) = generate(&mut OsRng);

// Encapsulate: creates shared secret + ciphertext
let (ciphertext, shared_secret_sender) = encapsulate(&public_key, &mut OsRng);

// Decapsulate: recovers shared secret from ciphertext
let shared_secret_receiver = decapsulate(&secret_key, &ciphertext);

assert_eq!(shared_secret_sender.as_bytes(), shared_secret_receiver.as_bytes());
```

## Examples

Run the included examples:

```bash
# Basic key encapsulation
cargo run --example basic -p sanct-ml-kem --features mlkem768

# ML-KEM + AES-256-GCM encryption
cargo run --example aes_encrypt -p sanct-ml-kem --features mlkem1024
```

## Development

```bash
# Run all tests
cargo test --workspace --all-features

# Run benchmarks
cargo bench -p sanct-ml-kem --features "mlkem512 mlkem768 mlkem1024"

# Check for issues
cargo clippy --workspace --all-features
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `ml-kem` | Enable ML-KEM (default) |
| `mlkem512` | ML-KEM-512 parameter set |
| `mlkem768` | ML-KEM-768 parameter set (default) |
| `mlkem1024` | ML-KEM-1024 parameter set |
| `std` | Enable standard library support |

## Security

This implementation prioritizes correctness and security:

- Constant-time operations to prevent timing side-channels
- Zeroization of sensitive data on drop
- No unsafe code

⚠️ **Note:** This library has not yet been audited. Use at your own risk in production systems.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
