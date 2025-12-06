use super::params::N;
use super::reduce::{barrett_reduce, cond_sub_q, montgomery_reduce};
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
pub struct Poly {
    pub coeffs: [i16; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self::new()
    }
}

impl Poly {
    pub const fn new() -> Self {
        Self { coeffs: [0i16; N] }
    }

    #[inline]
    pub fn reduce(&mut self) {
        for i in 0..N {
            self.coeffs[i] = barrett_reduce(self.coeffs[i]);
        }
    }

    #[inline]
    pub fn add(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] += b.coeffs[i];
        }
    }

    #[inline]
    pub fn sub(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] -= b.coeffs[i];
        }
    }

    #[inline]
    pub fn montgomery_reduce_coeffs(&mut self) {
        const F: i32 = 1353;
        for i in 0..N {
            self.coeffs[i] = montgomery_reduce(self.coeffs[i] as i32 * F);
        }
    }

    #[inline]
    pub fn cond_sub_q(&mut self) {
        for i in 0..N {
            self.coeffs[i] = cond_sub_q(self.coeffs[i]);
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
}
