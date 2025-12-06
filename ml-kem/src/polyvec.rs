use crate::ntt;
use crate::params::N;
use crate::poly::Poly;
use crate::reduce::barrett_reduce;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
pub struct PolyVec<const K: usize> {
    pub vec: [Poly; K],
}

impl<const K: usize> Default for PolyVec<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const K: usize> PolyVec<K> {
    pub fn new() -> Self {
        Self {
            vec: core::array::from_fn(|_| Poly::new()),
        }
    }

    pub fn ntt(&mut self) {
        for i in 0..K {
            ntt::ntt(&mut self.vec[i]);
        }
    }

    pub fn inv_ntt(&mut self) {
        for i in 0..K {
            ntt::inv_ntt(&mut self.vec[i]);
        }
    }

    pub fn reduce(&mut self) {
        for i in 0..K {
            self.vec[i].reduce();
        }
    }

    pub fn add(&mut self, b: &PolyVec<K>) {
        for i in 0..K {
            self.vec[i].add(&b.vec[i]);
        }
    }

    pub fn cond_sub_q(&mut self) {
        for i in 0..K {
            self.vec[i].cond_sub_q();
        }
    }

    pub fn pointwise_acc_montgomery(&self, b: &PolyVec<K>) -> Poly {
        let mut r = ntt::basemul(&self.vec[0], &b.vec[0]);
        for i in 1..K {
            let t = ntt::basemul(&self.vec[i], &b.vec[i]);
            r.add(&t);
        }
        for i in 0..N {
            r.coeffs[i] = barrett_reduce(r.coeffs[i]);
        }
        r
    }
}
