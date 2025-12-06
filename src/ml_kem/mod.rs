//! ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) implementation.
//!
//! This module implements FIPS 203 (ML-KEM), formerly known as CRYSTALS-Kyber.
//!
//! # Parameter Sets
//!
//! | Parameter Set | Security Level | Feature Flag |
//! |--------------|----------------|--------------|
//! | ML-KEM-512   | NIST Level 1   | `mlkem512`   |
//! | ML-KEM-768   | NIST Level 3   | `mlkem768`   |
//! | ML-KEM-1024  | NIST Level 5   | `mlkem1024`  |
//!
//! # Example
//!
//! ```
//! use rustpq::ml_kem::mlkem768::{generate, encapsulate, decapsulate};
//! use rand::rngs::OsRng;
//!
//! let (pk, sk) = generate(&mut OsRng);
//! let (ct, ss_sender) = encapsulate(&pk, &mut OsRng);
//! let ss_receiver = decapsulate(&sk, &ct);
//!
//! assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
//! ```

#![allow(clippy::needless_range_loop)]

mod compress;
mod encode;
mod error;
mod indcpa;
mod kem;
mod ntt;
mod params;
mod poly;
mod polyvec;
mod reduce;
mod sampling;
mod symmetric;

pub use error::Error;

#[cfg(feature = "mlkem512")]
pub mod mlkem512 {
    //! ML-KEM-512 (NIST Level 1 security).
    pub use super::kem::mlkem512::*;
}

#[cfg(feature = "mlkem768")]
pub mod mlkem768 {
    //! ML-KEM-768 (NIST Level 3 security).
    pub use super::kem::mlkem768::*;
}

#[cfg(feature = "mlkem1024")]
pub mod mlkem1024 {
    //! ML-KEM-1024 (NIST Level 5 security).
    pub use super::kem::mlkem1024::*;
}
