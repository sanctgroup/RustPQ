# RustPQ

A pure Rust post-quantum cryptography suite by [Sanct](https://github.com/sanctgroup).

[](https://crates.io/crates/rustpq)
[](https://docs.rs/rustpq)
[](https://www.google.com/search?q=LICENSE-MIT)

## Algorithms

| Algorithm | Standard | Status |
|-----------|----------|--------|
| ML-KEM (Kyber) | [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism](https://csrc.nist.gov/pubs/fips/203/final) | Implemented |
| ML-DSA (Dilithium) | [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final) | Coming soon |
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

## Examples

Run the included example:

```bash
# Basic key encapsulation
cargo run --example basic --features mlkem768
```

## Benchmarks

Benchmarks were performed on a Mac M5 Chip. Times represent the mean execution time per operation.

| Parameter Set | Keygen | Encapsulate | Decapsulate |
|---------------|--------|-------------|-------------|
| **ML-KEM-512** | 10.43 µs | 8.26 µs | 8.84 µs |
| **ML-KEM-768** | 16.45 µs | 13.68 µs | 14.70 µs |
| **ML-KEM-1024** | 25.45 µs | 20.93 µs | 22.97 µs |

To run the benchmarks locally:

```bash
cargo bench --features "mlkem512 mlkem768 mlkem1024"
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
