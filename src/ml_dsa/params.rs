pub const N: usize = 256;
pub const Q: i32 = 8380417;
pub const QINV: i32 = 58728449;
pub const D: usize = 13;
pub const ROOT_OF_UNITY: i32 = 1753;
pub const SEEDBYTES: usize = 32;
pub const CRHBYTES: usize = 64;
pub const TRBYTES: usize = 64;

pub trait Params {
    const K: usize;
    const L: usize;
    const ETA: usize;
    const TAU: usize;
    const BETA: usize;
    const GAMMA1: usize;
    const GAMMA2: usize;
    const OMEGA: usize;

    const POLYT1_PACKEDBYTES: usize;
    const POLYT0_PACKEDBYTES: usize;
    const POLYVECH_PACKEDBYTES: usize;
    const POLYZ_PACKEDBYTES: usize;
    const POLYW1_PACKEDBYTES: usize;
    const POLYETA_PACKEDBYTES: usize;

    const CRYPTO_PUBLICKEYBYTES: usize;
    const CRYPTO_SECRETKEYBYTES: usize;
    const CRYPTO_BYTES: usize;
}

#[allow(non_camel_case_types)]
pub struct ML_DSA_44;

impl Params for ML_DSA_44 {
    const K: usize = 4;
    const L: usize = 4;
    const ETA: usize = 2;
    const TAU: usize = 39;
    const BETA: usize = 78;
    const GAMMA1: usize = 1 << 17;
    const GAMMA2: usize = (Q as usize - 1) / 88;
    const OMEGA: usize = 80;

    const POLYT1_PACKEDBYTES: usize = 320;
    const POLYT0_PACKEDBYTES: usize = 416;
    const POLYVECH_PACKEDBYTES: usize = Self::OMEGA + Self::K;
    const POLYZ_PACKEDBYTES: usize = 576;
    const POLYW1_PACKEDBYTES: usize = 192;
    const POLYETA_PACKEDBYTES: usize = 96;

    const CRYPTO_PUBLICKEYBYTES: usize = SEEDBYTES + Self::K * Self::POLYT1_PACKEDBYTES;
    const CRYPTO_SECRETKEYBYTES: usize = 2 * SEEDBYTES
        + TRBYTES
        + Self::L * Self::POLYETA_PACKEDBYTES
        + Self::K * Self::POLYETA_PACKEDBYTES
        + Self::K * Self::POLYT0_PACKEDBYTES;
    const CRYPTO_BYTES: usize =
        SEEDBYTES + Self::L * Self::POLYZ_PACKEDBYTES + Self::POLYVECH_PACKEDBYTES;
}

#[allow(non_camel_case_types)]
pub struct ML_DSA_65;

impl Params for ML_DSA_65 {
    const K: usize = 6;
    const L: usize = 5;
    const ETA: usize = 4;
    const TAU: usize = 49;
    const BETA: usize = 196;
    const GAMMA1: usize = 1 << 19;
    const GAMMA2: usize = (Q as usize - 1) / 32;
    const OMEGA: usize = 55;

    const POLYT1_PACKEDBYTES: usize = 320;
    const POLYT0_PACKEDBYTES: usize = 416;
    const POLYVECH_PACKEDBYTES: usize = Self::OMEGA + Self::K;
    const POLYZ_PACKEDBYTES: usize = 640;
    const POLYW1_PACKEDBYTES: usize = 128;
    const POLYETA_PACKEDBYTES: usize = 128;

    const CRYPTO_PUBLICKEYBYTES: usize = SEEDBYTES + Self::K * Self::POLYT1_PACKEDBYTES;
    const CRYPTO_SECRETKEYBYTES: usize = 2 * SEEDBYTES
        + TRBYTES
        + Self::L * Self::POLYETA_PACKEDBYTES
        + Self::K * Self::POLYETA_PACKEDBYTES
        + Self::K * Self::POLYT0_PACKEDBYTES;
    const CRYPTO_BYTES: usize =
        SEEDBYTES + Self::L * Self::POLYZ_PACKEDBYTES + Self::POLYVECH_PACKEDBYTES;
}

#[allow(non_camel_case_types)]
pub struct ML_DSA_87;

impl Params for ML_DSA_87 {
    const K: usize = 8;
    const L: usize = 7;
    const ETA: usize = 2;
    const TAU: usize = 60;
    const BETA: usize = 120;
    const GAMMA1: usize = 1 << 19;
    const GAMMA2: usize = (Q as usize - 1) / 32;
    const OMEGA: usize = 75;

    const POLYT1_PACKEDBYTES: usize = 320;
    const POLYT0_PACKEDBYTES: usize = 416;
    const POLYVECH_PACKEDBYTES: usize = Self::OMEGA + Self::K;
    const POLYZ_PACKEDBYTES: usize = 640;
    const POLYW1_PACKEDBYTES: usize = 128;
    const POLYETA_PACKEDBYTES: usize = 96;

    const CRYPTO_PUBLICKEYBYTES: usize = SEEDBYTES + Self::K * Self::POLYT1_PACKEDBYTES;
    const CRYPTO_SECRETKEYBYTES: usize = 2 * SEEDBYTES
        + TRBYTES
        + Self::L * Self::POLYETA_PACKEDBYTES
        + Self::K * Self::POLYETA_PACKEDBYTES
        + Self::K * Self::POLYT0_PACKEDBYTES;
    const CRYPTO_BYTES: usize =
        SEEDBYTES + Self::L * Self::POLYZ_PACKEDBYTES + Self::POLYVECH_PACKEDBYTES;
}
