# RustPQ

A pure Rust post-quantum cryptography suite by [Sanct](https://github.com/sanctgroup).

[![CI](https://github.com/sanctgroup/RustPQ/actions/workflows/ci.yml/badge.svg)](https://github.com/sanctgroup/RustPQ/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/rustpq.svg)](https://crates.io/crates/rustpq)
[![Docs.rs](https://docs.rs/rustpq/badge.svg)](https://docs.rs/rustpq)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://opensource.org/licenses/MIT)

## Algorithms

| Algorithm | Standard | Status |
|-----------|----------|--------|
| ML-KEM (Kyber) | [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism](https://csrc.nist.gov/pubs/fips/203/final) | Implemented |
| ML-DSA (Dilithium) | [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final) | Implemented |
| SLH-DSA (SPHINCS+) | [FIPS 205: Stateless Hash-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/205/final) | Planned |

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

### ML-DSA Digital Signatures

```rust
use rustpq::ml_dsa::sign::mldsa44::{generate, sign, verify};
use rand::rngs::OsRng;

// Generate a keypair
let (public_key, secret_key) = generate(&mut OsRng);

// Sign a message
let message = b"Hello World";
let context = b""; // Optional context string
let signature = sign(&secret_key, message, context, &mut OsRng).unwrap();

// Verify the signature
assert!(verify(&public_key, message, context, &signature).is_ok());
```

## Examples

Run the included examples:

```bash
# ML-KEM key encapsulation
cargo run --example basic --features mlkem768

# ML-DSA digital signatures
cargo run --example mldsa --features mldsa44
```

## Development

```bash
# Run all tests
cargo test --all-features

# Check for issues
cargo clippy --all-features
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `ml-kem` | Enable ML-KEM (default) |
| `mlkem512` | ML-KEM-512 parameter set |
| `mlkem768` | ML-KEM-768 parameter set (default) |
| `mlkem1024` | ML-KEM-1024 parameter set |
| `ml-dsa` | Enable ML-DSA |
| `mldsa44` | ML-DSA-44 parameter set (NIST Level 2) |
| `mldsa65` | ML-DSA-65 parameter set (NIST Level 3) |
| `mldsa87` | ML-DSA-87 parameter set (NIST Level 5) |
| `std` | Enable standard library support |

## Security

This implementation prioritizes correctness and security:

  - Constant-time operations to prevent timing side-channels
  - Zeroization of sensitive data on drop
  - No unsafe code

> [\!WARNING]
> This library has not yet been audited. Use at your own risk in production systems.

## License

Licensed under either of:

  - Apache License, Version 2.0 ([LICENSE-APACHE](https://www.google.com/search?q=LICENSE-APACHE))
  - MIT license ([LICENSE-MIT](https://www.google.com/search?q=LICENSE-MIT))

at your option.
