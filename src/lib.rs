#![no_std]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "ml-kem")]
pub mod ml_kem;

#[cfg(feature = "ml-dsa")]
pub mod ml_dsa;
