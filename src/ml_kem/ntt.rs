use crate::ml_kem::params::N;
use super::poly::Poly;
use crate::ml_kem::reduce::{barrett_reduce, montgomery_reduce};

const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

#[inline]
fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(a as i32 * b as i32)
}

#[inline]
pub fn ntt(p: &mut Poly) {
    let mut k = 1usize;
    let mut len = 128usize;

    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..(start + len) {
                let t = fqmul(zeta, p.coeffs[j + len]);
                p.coeffs[j + len] = p.coeffs[j] - t;
                p.coeffs[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

#[inline]
pub fn inv_ntt(p: &mut Poly) {
    let mut k = 127usize;
    let mut len = 2usize;

    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);
            for j in start..(start + len) {
                let t = p.coeffs[j];
                p.coeffs[j] = barrett_reduce(t + p.coeffs[j + len]);
                p.coeffs[j + len] = fqmul(zeta, p.coeffs[j + len] - t);
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    const F: i16 = 1441;
    for i in 0..N {
        p.coeffs[i] = fqmul(p.coeffs[i], F);
    }
}

#[inline]
fn basemul_elem(a0: i16, a1: i16, b0: i16, b1: i16, zeta: i16) -> (i16, i16) {
    let r0 = fqmul(a1, b1);
    let r0 = fqmul(r0, zeta);
    let r0 = r0 + fqmul(a0, b0);
    let r1 = fqmul(a0, b1);
    let r1 = r1 + fqmul(a1, b0);
    (r0, r1)
}

#[inline]
pub fn basemul(a: &Poly, b: &Poly) -> Poly {
    let mut r = Poly::new();

    for i in 0..N / 4 {
        let zeta = ZETAS[64 + i];
        let (r0, r1) = basemul_elem(
            a.coeffs[4 * i],
            a.coeffs[4 * i + 1],
            b.coeffs[4 * i],
            b.coeffs[4 * i + 1],
            zeta,
        );
        r.coeffs[4 * i] = r0;
        r.coeffs[4 * i + 1] = r1;

        let (r2, r3) = basemul_elem(
            a.coeffs[4 * i + 2],
            a.coeffs[4 * i + 3],
            b.coeffs[4 * i + 2],
            b.coeffs[4 * i + 3],
            -zeta,
        );
        r.coeffs[4 * i + 2] = r2;
        r.coeffs[4 * i + 3] = r3;
    }

    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_kem::params::{N, Q};
    use crate::ml_kem::reduce::barrett_reduce;
    const MONT: i32 = 2285;

    #[test]
    fn test_ntt_inv_ntt() {
        let mut p = Poly::new();
        p.coeffs[0] = 1;
        p.coeffs[1] = 2;
        p.coeffs[2] = 3;
        let orig = p.clone();

        ntt(&mut p);
        inv_ntt(&mut p);

        for i in 0..N {
            p.coeffs[i] = barrett_reduce(p.coeffs[i]);
            if p.coeffs[i] < 0 {
                p.coeffs[i] += Q;
            }
        }

        for i in 0..3 {
            let expected = ((orig.coeffs[i] as i32 * MONT) % Q as i32) as i16;
            let actual = p.coeffs[i];
            assert_eq!(
                actual, expected,
                "mismatch at {}: got {}, expected {} (orig * R)",
                i, actual, expected
            );
        }
        for i in 3..N {
            assert_eq!(p.coeffs[i], 0, "non-zero at {}: {}", i, p.coeffs[i]);
        }
    }
}
