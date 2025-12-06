#![no_std]
#![forbid(unsafe_code)]
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
    pub use crate::kem::mlkem512::*;
}

#[cfg(feature = "mlkem768")]
pub mod mlkem768 {
    pub use crate::kem::mlkem768::*;
}

#[cfg(feature = "mlkem1024")]
pub mod mlkem1024 {
    pub use crate::kem::mlkem1024::*;
}
