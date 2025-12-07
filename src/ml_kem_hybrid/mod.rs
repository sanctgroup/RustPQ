//! ML-KEM Hybrid Key-Encapsulation Mechanisms.
//!
//! This module implements hybrid KEMs combining ML-KEM with traditional
//! elliptic curve Diffie-Hellman, following IETF specifications.
//!
//! Hybrid KEMs provide defense-in-depth: even if one algorithm is broken,
//! the other still provides security.
//!
//! # Hybrid Combinations
//!
//! | Hybrid | Security Level | Feature Flag | Shared Secret |
//! |--------|----------------|--------------|---------------|
//! | X25519MLKEM768 | NIST Level 3 | `x25519-mlkem768` | 64 bytes |
//! | SecP256r1MLKEM768 | NIST Level 3 | `p256-mlkem768` | 64 bytes |
//! | SecP384r1MLKEM1024 | NIST Level 5 | `p384-mlkem1024` | 80 bytes |
//!
//! # Combiner Construction
//!
//! - X25519MLKEM768: `ss = mlkem_ss || x25519_ss`
//! - SecP256r1MLKEM768: `ss = ecdh_ss || mlkem_ss`
//! - SecP384r1MLKEM1024: `ss = ecdh_ss || mlkem_ss`
//!
//! Use `derive_key()` for a ready-to-use 32-byte key (SHA3-256),
//! or `as_bytes()` for protocol integration or custom KDF.
//!
//! # Example
//!
//! ```ignore
//! use rustpq::ml_kem_hybrid::x25519_mlkem768::{generate, encapsulate, decapsulate};
//! use rand::rngs::OsRng;
//!
//! let (pk, sk) = generate(&mut OsRng);
//! let (ct, ss_sender) = encapsulate(&pk, &mut OsRng);
//! let ss_receiver = decapsulate(&sk, &ct);
//!
//! // Ready-to-use 32-byte key
//! let key = ss_sender.derive_key();
//! ```

mod error;

#[cfg(feature = "x25519-mlkem768")]
pub mod x25519_mlkem768;

#[cfg(feature = "p256-mlkem768")]
pub mod p256_mlkem768;

#[cfg(feature = "p384-mlkem1024")]
pub mod p384_mlkem1024;

pub use error::Error;
