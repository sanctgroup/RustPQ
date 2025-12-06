use crate::ml_dsa::params::{Q, QINV};

#[inline(always)]
pub fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(QINV);
    let t_q = (t as i64).wrapping_mul(Q as i64);
    let r = (a.wrapping_sub(t_q)) >> 32;
    r as i32
}

#[inline]
pub fn reduce32(a: i32) -> i32 {
    // Correct reduction for Q = 8380417
    // This computes t approx a / 2^23, which is close to a / Q
    let t = (a + (1 << 22)) >> 23;
    let t = a - t * Q;
    t
}

#[inline]
pub fn caddq(a: i32) -> i32 {
    a + ((a >> 31) & Q)
}

#[inline]
pub fn freeze(mut a: i32) -> i32 {
    a = reduce32(a);
    a = caddq(a);
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_dsa::params::Q;

    #[test]
    fn test_montgomery_reduce() {
        let a: i64 = 100_000_000_000;
        let r = montgomery_reduce(a);
        assert!(r.abs() < Q);

        let a: i64 = -100_000_000_000;
        let r = montgomery_reduce(a);
        assert!(r.abs() < Q);
    }

    #[test]
    fn test_reduce32_basic() {
        let a = 8380417 + 100;
        let r = reduce32(a);
        assert_eq!(r, 100);

        let a = -100;
        let r = reduce32(a);
        // reduce32 output is not guaranteed to be positive, but congruent
        assert_eq!(r + Q, Q - 100);
    }
}
