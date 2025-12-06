use crate::ml_dsa::ntt::{invntt_tomont, ntt};
use crate::ml_dsa::params::{N, Q};
use crate::ml_dsa::poly::Poly;
use crate::ml_dsa::reduce::montgomery_reduce;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct PolyVec<const K: usize> {
    pub vec: [Poly; K],
}

impl<const K: usize> PolyVec<K> {
    pub fn new() -> Self {
        Self {
            vec: core::array::from_fn(|_| Poly::new()),
        }
    }

    pub fn reduce(&mut self) {
        for i in 0..K {
            self.vec[i].reduce();
        }
    }

    pub fn freeze(&mut self) {
        for i in 0..K {
            self.vec[i].freeze_coeffs();
        }
    }

    pub fn from_montgomery(&mut self) {
        for i in 0..K {
            self.vec[i].from_montgomery();
        }
    }

    pub fn to_mont(&self) -> PolyVec<K> {
        const Q128: i128 = Q as i128;
        const R2_MOD_Q: i64 = ((1_i128 << 64) % Q128) as i64;
        let mut result = self.clone();
        for i in 0..K {
            for j in 0..N {
                let val = self.vec[i].coeffs[j] as i64;
                result.vec[i].coeffs[j] = montgomery_reduce(val * R2_MOD_Q);
            }
        }
        result
    }

    pub fn add(&mut self, b: &PolyVec<K>) {
        for i in 0..K {
            self.vec[i].add(&b.vec[i]);
        }
    }

    pub fn ntt(&mut self) {
        for i in 0..K {
            ntt(&mut self.vec[i].coeffs);
        }
    }

    pub fn invntt_tomont(&mut self) {
        for i in 0..K {
            invntt_tomont(&mut self.vec[i].coeffs);
        }
    }

    pub fn pointwise_poly_montgomery(&self, a: &Poly) -> PolyVec<K> {
        let mut r = PolyVec::new();
        for i in 0..K {
            r.vec[i] = Poly::pointwise_montgomery(&self.vec[i], a);
        }
        r
    }

    pub fn chknorm(&self, bound: i32) -> bool {
        for i in 0..K {
            if self.vec[i].chknorm(bound) {
                return true;
            }
        }
        false
    }

    pub fn infinity_norm(&self) -> i32 {
        let mut max_norm = 0i32;
        for i in 0..K {
            for j in 0..N {
                let coeff = self.vec[i].coeffs[j];
                let centered = if coeff > Q / 2 {
                    Q - coeff
                } else if coeff < -(Q / 2) {
                    coeff + Q
                } else {
                    coeff
                };
                max_norm = max_norm.max(centered.abs());
            }
        }
        max_norm
    }

    pub fn uniform_eta<const ETA: usize>(&mut self, seed: &[u8; 64], nonce: u16) {
        for i in 0..K {
            self.vec[i].uniform_eta::<ETA>(seed, nonce + i as u16);
        }
    }

    pub fn uniform_gamma1<const GAMMA1: usize>(&mut self, seed: &[u8; 64], nonce: u16) {
        for i in 0..K {
            self.vec[i].uniform_gamma1::<GAMMA1>(seed, nonce + i as u16);
        }
    }
}

impl<const K: usize> Default for PolyVec<K> {
    fn default() -> Self {
        Self::new()
    }
}

pub fn polyvec_matrix_pointwise_montgomery<const K: usize, const L: usize>(
    mat: &[PolyVec<L>; K],
    v: &PolyVec<L>,
) -> PolyVec<K> {
    let mut r = PolyVec::<K>::new();
    let v_mont = v.to_mont();

    for i in 0..K {
        r.vec[i] = Poly::pointwise_montgomery(&mat[i].vec[0], &v_mont.vec[0]);
        for j in 1..L {
            let t = Poly::pointwise_montgomery(&mat[i].vec[j], &v_mont.vec[j]);
            r.vec[i].add(&t);
        }
    }

    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polyvec_add() {
        let mut a = PolyVec::<4>::new();
        let mut b = PolyVec::<4>::new();
        a.vec[0].coeffs[0] = 100;
        b.vec[0].coeffs[0] = 50;
        a.add(&b);
        assert_eq!(a.vec[0].coeffs[0], 150);
    }

    #[test]
    fn test_polyvec_chknorm() {
        let mut a = PolyVec::<4>::new();
        a.vec[0].coeffs[0] = 100;
        assert!(!a.chknorm(200));
        assert!(a.chknorm(50));
    }
}
