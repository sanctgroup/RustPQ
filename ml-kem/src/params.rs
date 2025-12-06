pub const Q: i16 = 3329;
pub const N: usize = 256;

pub const Q32: i32 = Q as i32;

pub const SYMBYTES: usize = 32;
pub const POLYBYTES: usize = 384;

#[cfg(feature = "mlkem512")]
pub mod mlkem512 {
    pub const K: usize = 2;
    pub const ETA1: usize = 3;
    pub const ETA2: usize = 2;
    pub const DU: usize = 10;
    pub const DV: usize = 4;

    pub const PUBLICKEYBYTES: usize = super::POLYBYTES * K + super::SYMBYTES;
    pub const SECRETKEYBYTES: usize = super::POLYBYTES * K + PUBLICKEYBYTES + 2 * super::SYMBYTES;
    pub const CIPHERTEXTBYTES: usize = super::N * K * DU / 8 + super::N * DV / 8;
}

#[cfg(feature = "mlkem768")]
pub mod mlkem768 {
    pub const K: usize = 3;
    pub const ETA1: usize = 2;
    pub const ETA2: usize = 2;
    pub const DU: usize = 10;
    pub const DV: usize = 4;

    pub const PUBLICKEYBYTES: usize = super::POLYBYTES * K + super::SYMBYTES;
    pub const SECRETKEYBYTES: usize = super::POLYBYTES * K + PUBLICKEYBYTES + 2 * super::SYMBYTES;
    pub const CIPHERTEXTBYTES: usize = super::N * K * DU / 8 + super::N * DV / 8;
}

#[cfg(feature = "mlkem1024")]
pub mod mlkem1024 {
    pub const K: usize = 4;
    pub const ETA1: usize = 2;
    pub const ETA2: usize = 2;
    pub const DU: usize = 11;
    pub const DV: usize = 5;

    pub const PUBLICKEYBYTES: usize = super::POLYBYTES * K + super::SYMBYTES;
    pub const SECRETKEYBYTES: usize = super::POLYBYTES * K + PUBLICKEYBYTES + 2 * super::SYMBYTES;
    pub const CIPHERTEXTBYTES: usize = super::N * K * DU / 8 + super::N * DV / 8;
}
