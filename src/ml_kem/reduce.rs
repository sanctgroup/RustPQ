use crate::ml_kem::params::Q;

const QINV: i16 = -3327;

#[inline]
#[allow(dead_code)]
pub fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(QINV);
    let t = (a - (t as i32) * (Q as i32)) >> 16;
    t as i16
}

#[inline]
pub fn barrett_reduce(a: i16) -> i16 {
    const V: i32 = 20159;
    let t = (V * a as i32 + (1 << 25)) >> 26;
    (a as i32 - t * Q as i32) as i16
}

#[inline]
#[allow(dead_code)]
pub fn cond_sub_q(a: i16) -> i16 {
    let mut x = a;
    x -= Q;
    x += (x >> 15) & Q;
    x
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_kem::params::Q;

    #[test]
    fn test_barrett_reduce() {
        for i in -32768i16..32767 {
            let r = barrett_reduce(i);
            assert!(
                r >= -Q && r < Q,
                "result {} out of range for input {}",
                r,
                i
            );
            let i_mod = ((i % Q) + Q) % Q;
            let r_mod = ((r % Q) + Q) % Q;
            assert_eq!(i_mod, r_mod, "mismatch for input {}", i);
        }
    }

    #[test]
    fn test_montgomery_reduce() {
        const MONT: i32 = 2285;
        let a = 1000i32 * MONT;
        let r = montgomery_reduce(a);
        assert!(r.abs() < Q);
    }
}
