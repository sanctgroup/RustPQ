//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm) implementation.
//!
//! This module implements FIPS 204 (ML-DSA), formerly known as CRYSTALS-Dilithium.
//!
//! # Parameter Sets
//!
//! | Parameter Set | Security Level | Feature Flag |
//! |--------------|----------------|--------------|
//! | ML-DSA-44    | NIST Level 2   | `mldsa44`    |
//! | ML-DSA-65    | NIST Level 3   | `mldsa65`    |
//! | ML-DSA-87    | NIST Level 5   | `mldsa87`    |
//!
//! # Example
//!
//! ```
//! use rustpq::ml_dsa::mldsa44::{generate, sign, verify};
//! use rand::rngs::OsRng;
//!
//! let (pk, sk) = generate(&mut OsRng);
//! let message = b"Hello World";
//! let signature = sign(&sk, message, b"", &mut OsRng).unwrap();
//!
//! assert!(verify(&pk, message, b"", &signature).is_ok());
//! ```

#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]

mod ntt;
mod packing;
mod params;
mod poly;
mod polyvec;
mod reduce;
mod rounding;
mod sampling;
mod symmetric;

pub mod error;
pub mod sign;

pub use error::Error;

#[cfg(feature = "mldsa44")]
pub mod mldsa44 {
    //! ML-DSA-44 (NIST Level 2 security).
    pub use super::sign::mldsa44::*;
}

#[cfg(feature = "mldsa65")]
pub mod mldsa65 {
    //! ML-DSA-65 (NIST Level 3 security).
    pub use super::sign::mldsa65::*;
}

#[cfg(feature = "mldsa87")]
pub mod mldsa87 {
    //! ML-DSA-87 (NIST Level 5 security).
    pub use super::sign::mldsa87::*;
}
