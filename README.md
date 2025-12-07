# RustPQ

A pure Rust post-quantum cryptography suite by [Sanct](https://github.com/sanctgroup).

[![CI](https://github.com/sanctgroup/RustPQ/actions/workflows/ci.yml/badge.svg)](https://github.com/sanctgroup/RustPQ/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/rustpq.svg)](https://crates.io/crates/rustpq)
[![Docs.rs](https://docs.rs/rustpq/badge.svg)](https://docs.rs/rustpq)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://opensource.org/licenses/MIT)

## Algorithms

| Algorithm | Standard | Status |
|-----------|----------|--------|
| ML-KEM (Kyber) | [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | Implemented |
| ML-KEM Hybrid | [IETF draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/) | Implemented |
| ML-DSA (Dilithium) | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | Implemented |
| SLH-DSA (SPHINCS+) | [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) | Planned |

## Features

  - **Pure Rust** - No unsafe code, memory-safe by design
  - **`no_std` Compatible** - Works on embedded devices and bare-metal
  - **Constant-time** - Resistant to timing attacks via the `subtle` crate
  - **Lightweight** - Minimal dependencies

## Installation

```toml
[dependencies]
rustpq = "0.3.0"
```

For hybrid KEMs:

```toml
[dependencies]
rustpq = { version = "0.3.0", features = ["x25519-mlkem768"] }
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

### ML-KEM Hybrid (Post-Quantum + Classical)

Hybrid KEMs combine ML-KEM with traditional ECDH for defense-in-depth. Even if one algorithm is broken, the other provides security.

```rust
use rustpq::ml_kem_hybrid::x25519_mlkem768::{generate, encapsulate, decapsulate};
use rand::rngs::OsRng;

// Generate hybrid keypair (X25519 + ML-KEM-768)
let (pk, sk) = generate(&mut OsRng);

// Encapsulate
let (ct, ss_sender) = encapsulate(&pk, &mut OsRng);

// Decapsulate
let ss_receiver = decapsulate(&sk, &ct);

// Get a ready-to-use 32-byte key (SHA3-256 of combined secrets)
let key = ss_sender.derive_key();

// Or access raw concatenated secret for custom KDF
let raw_64_bytes = ss_sender.as_bytes();
```

### ML-DSA Digital Signatures

```rust
use rustpq::ml_dsa::mldsa44::{generate, sign, verify};
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

```bash
# ML-KEM key encapsulation
cargo run --example basic --features mlkem768

# ML-KEM hybrid (X25519 + ML-KEM-768)
cargo run --example hybrid --features x25519-mlkem768

# End-to-end encryption (hybrid KEM + signatures)
cargo run --example e2ee --features "x25519-mlkem768,mldsa65"

# ML-DSA digital signatures
cargo run --example mldsa --features mldsa44
```

## Development

```bash
# Run all tests
cargo test --all-features

# Run hybrid tests only
cargo test --features "x25519-mlkem768,p256-mlkem768,p384-mlkem1024"

# Benchmarks
cargo bench --features "mlkem512,mlkem768,mlkem1024"
cargo bench --features "x25519-mlkem768,p256-mlkem768,p384-mlkem1024"

# Check for issues
cargo clippy --all-features
```

## Feature Flags

### ML-KEM (Key Encapsulation)

| Feature | Algorithm | Security | Key Size | Ciphertext | Secret |
|---------|-----------|----------|----------|------------|--------|
| `mlkem512` | ML-KEM-512 | Level 1 (~AES-128) | 800 B | 768 B | 32 B |
| `mlkem768` | ML-KEM-768 | Level 3 (~AES-192) | 1184 B | 1088 B | 32 B |
| `mlkem1024` | ML-KEM-1024 | Level 5 (~AES-256) | 1568 B | 1568 B | 32 B |

### ML-KEM Hybrid (Post-Quantum + Classical)

| Feature | Hybrid | Security | Key Size | Ciphertext | Secret |
|---------|--------|----------|----------|------------|--------|
| `x25519-mlkem768` | X25519 + ML-KEM-768 | Level 3 | 1216 B | 1120 B | 64 B |
| `p256-mlkem768` | P-256 + ML-KEM-768 | Level 3 | 1249 B | 1153 B | 64 B |
| `p384-mlkem1024` | P-384 + ML-KEM-1024 | Level 5 | 1665 B | 1665 B | 80 B |

> Hybrid combiners follow [IETF draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/). Use `derive_key()` for a ready-to-use 32-byte key, or `as_bytes()` for protocol integration or custom KDF.

### ML-DSA (Digital Signatures)

| Feature | Algorithm | Security | Key Size | Signature |
|---------|-----------|----------|----------|-----------|
| `mldsa44` | ML-DSA-44 | Level 2 | 2560 B | 2420 B |
| `mldsa65` | ML-DSA-65 | Level 3 | 4032 B | 3309 B |
| `mldsa87` | ML-DSA-87 | Level 5 | 4896 B | 4627 B |

### General

| Feature | Description |
|---------|-------------|
| `ml-kem` | Enable ML-KEM module (default) |
| `ml-kem-hybrid` | Enable ML-KEM Hybrid module |
| `ml-dsa` | Enable ML-DSA module |
| `std` | Enable standard library support |
| `alloc` | Enable allocator support |

**Default features:** `ml-kem`, `mlkem768`

## Security

This implementation prioritizes correctness and security:

  - Constant-time operations to prevent timing side-channels
  - Zeroization of sensitive data on drop
  - No unsafe code
  - Hybrid KEMs provide defense-in-depth against both classical and quantum attacks

> [!WARNING]
> This library has not yet been audited. Use at your own risk in production systems.

## License

Licensed under either of:

  - Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
  - MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
