use crate::ml_dsa::ntt::{invntt_tomont, ntt};
use crate::ml_dsa::params::{N, Q};
use crate::ml_dsa::reduce::{freeze, montgomery_reduce, reduce32};
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self::new()
    }
}

impl Poly {
    pub const fn new() -> Self {
        Self { coeffs: [0i32; N] }
    }

    pub fn reduce(&mut self) {
        for i in 0..N {
            self.coeffs[i] = reduce32(self.coeffs[i]);
        }
    }

    pub fn freeze_coeffs(&mut self) {
        for i in 0..N {
            self.coeffs[i] = freeze(self.coeffs[i]);
        }
    }

    pub fn reduce_montgomery(&mut self) {
        for i in 0..N {
            self.coeffs[i] = montgomery_reduce(self.coeffs[i] as i64);
        }
    }

    pub fn add(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] += b.coeffs[i];
        }
    }

    pub fn sub(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] -= b.coeffs[i];
        }
    }

    pub fn ntt(&mut self) {
        ntt(&mut self.coeffs);
    }

    pub fn invntt_tomont(&mut self) {
        invntt_tomont(&mut self.coeffs);
    }

    pub fn pointwise_montgomery(a: &Poly, b: &Poly) -> Poly {
        let mut r = Poly::new();
        for i in 0..N {
            r.coeffs[i] = montgomery_reduce(a.coeffs[i] as i64 * b.coeffs[i] as i64);
        }
        r
    }

    pub fn chknorm(&self, bound: i32) -> bool {
        for i in 0..N {
            let coeff = self.coeffs[i];
            let centered = if coeff > Q / 2 {
                Q - coeff
            } else if coeff < -(Q / 2) {
                Q + coeff
            } else {
                coeff
            };

            if centered.abs() >= bound {
                return true;
            }
        }
        false
    }

    pub fn uniform_eta<const ETA: usize>(&mut self, seed: &[u8; 64], nonce: u16) {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        use sha3::Shake256;

        let mut state = Shake256::default();
        state.update(seed);
        state.update(&nonce.to_le_bytes());
        let mut reader = state.finalize_xof();

        let poly_uniform_eta_nblocks = if ETA == 2 { 2 } else { 4 };
        let mut buf = [0u8; 4 * 136];
        let buflen = poly_uniform_eta_nblocks * 136;
        reader.read(&mut buf[..buflen]);

        let mut ctr = 0;
        let mut pos = 0;

        while ctr < N {
            if ETA == 2 {
                let t0 = (buf[pos] & 0x0F) as i32;
                let t1 = (buf[pos] >> 4) as i32;
                pos += 1;

                if t0 < 15 {
                    let t0 = t0 % 5;
                    self.coeffs[ctr] = 2 - t0;
                    ctr += 1;
                }
                if t1 < 15 && ctr < N {
                    let t1 = t1 % 5;
                    self.coeffs[ctr] = 2 - t1;
                    ctr += 1;
                }
            } else {
                let t0 = (buf[pos] & 0x0F) as i32;
                let t1 = (buf[pos] >> 4) as i32;
                pos += 1;

                if t0 < 9 {
                    self.coeffs[ctr] = 4 - t0;
                    ctr += 1;
                }
                if t1 < 9 && ctr < N {
                    self.coeffs[ctr] = 4 - t1;
                    ctr += 1;
                }
            }

            if pos >= buflen && ctr < N {
                reader.read(&mut buf[..buflen]);
                pos = 0;
            }
        }
    }

    pub fn uniform_gamma1<const GAMMA1: usize>(&mut self, seed: &[u8; 64], nonce: u16) {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        use sha3::Shake256;

        let mut state = Shake256::default();
        state.update(seed);
        state.update(&nonce.to_le_bytes());
        let mut reader = state.finalize_xof();

        let polyeta_packedbytes = if GAMMA1 == (1 << 17) { 576 } else { 640 };
        let mut buf = [0u8; 640];
        reader.read(&mut buf[..polyeta_packedbytes]);

        if GAMMA1 == (1 << 17) {
            let mut pos = 0;
            for i in 0..N / 4 {
                let t0 = (buf[pos] as u32)
                    | ((buf[pos + 1] as u32) << 8)
                    | ((buf[pos + 2] as u32) << 16);
                let t1 = ((buf[pos + 2] as u32) >> 2)
                    | ((buf[pos + 3] as u32) << 6)
                    | ((buf[pos + 4] as u32) << 14);
                let t2 = ((buf[pos + 4] as u32) >> 4)
                    | ((buf[pos + 5] as u32) << 4)
                    | ((buf[pos + 6] as u32) << 12);
                let t3 = ((buf[pos + 6] as u32) >> 6)
                    | ((buf[pos + 7] as u32) << 2)
                    | ((buf[pos + 8] as u32) << 10);

                self.coeffs[4 * i] = (GAMMA1 as u32).wrapping_sub(t0 & 0x3FFFF) as i32;
                self.coeffs[4 * i + 1] = (GAMMA1 as u32).wrapping_sub(t1 & 0x3FFFF) as i32;
                self.coeffs[4 * i + 2] = (GAMMA1 as u32).wrapping_sub(t2 & 0x3FFFF) as i32;
                self.coeffs[4 * i + 3] = (GAMMA1 as u32).wrapping_sub(t3 & 0x3FFFF) as i32;

                pos += 9;
            }
        } else {
            let mut pos = 0;
            for i in 0..N / 2 {
                let t0 = (buf[pos] as u32)
                    | ((buf[pos + 1] as u32) << 8)
                    | ((buf[pos + 2] as u32) << 16);
                let t1 = (buf[pos + 2] as u32)
                    | ((buf[pos + 3] as u32) << 8)
                    | ((buf[pos + 4] as u32) << 16);

                self.coeffs[2 * i] = (GAMMA1 as u32).wrapping_sub(t0 & 0xFFFFF) as i32;
                self.coeffs[2 * i + 1] = (GAMMA1 as u32).wrapping_sub((t1 >> 4) & 0xFFFFF) as i32;

                pos += 5;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_add_sub() {
        let mut a = Poly::new();
        let mut b = Poly::new();
        a.coeffs[0] = 100;
        b.coeffs[0] = 50;
        a.add(&b);
        assert_eq!(a.coeffs[0], 150);
        a.sub(&b);
        assert_eq!(a.coeffs[0], 100);
    }

    #[test]
    fn test_poly_reduce() {
        let mut a = Poly::new();
        a.coeffs[0] = 100;
        a.reduce();
        assert!(a.coeffs[0].abs() <= Q);
    }

    #[test]
    fn test_chknorm() {
        let mut a = Poly::new();
        a.coeffs[0] = 100;
        assert!(!a.chknorm(200));
        assert!(a.chknorm(50));
    }
}
