use crate::ml_dsa::params::N;
use crate::ml_dsa::poly::Poly;
use crate::ml_dsa::polyvec::PolyVec;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;

pub fn expand_a<const K: usize, const L: usize>(rho: &[u8; 32]) -> [PolyVec<L>; K] {
    let mut mat: [PolyVec<L>; K] = core::array::from_fn(|_| PolyVec::new());

    for i in 0..K {
        for j in 0..L {
            poly_uniform(&mut mat[i].vec[j], rho, (i as u16) << 8 | (j as u16));
        }
    }

    mat
}

pub fn poly_uniform(a: &mut Poly, seed: &[u8; 32], nonce: u16) {
    use crate::ml_dsa::params::Q;

    let mut state = Shake128::default();
    state.update(seed);
    state.update(&nonce.to_le_bytes());
    let mut reader = state.finalize_xof();

    const SHAKE128_RATE: usize = 168;
    let mut buf = [0u8; SHAKE128_RATE * 5];
    reader.read(&mut buf);

    let mut ctr = 0;
    let mut pos = 0;

    while ctr < N {
        if pos + 3 > buf.len() {
            reader.read(&mut buf);
            pos = 0;
        }

        let t = (buf[pos] as u32)
            | ((buf[pos + 1] as u32) << 8)
            | (((buf[pos + 2] as u32) & 0x7F) << 16);
        pos += 3;

        if t < Q as u32 {
            a.coeffs[ctr] = t as i32;
            ctr += 1;
        }
    }
}

pub fn challenge<const TAU: usize>(c: &mut Poly, seed: &[u8; 32]) {
    use sha3::Shake256;

    let mut state = Shake256::default();
    state.update(seed);
    let mut reader = state.finalize_xof();

    let mut buf = [0u8; 136];
    reader.read(&mut buf);

    let mut signs = 0u64;
    for i in 0..8 {
        signs |= (buf[i] as u64) << (8 * i);
    }

    let mut pos = 8;
    for i in 0..N {
        c.coeffs[i] = 0;
    }

    for i in (N - TAU)..N {
        let mut b;
        loop {
            if pos >= buf.len() {
                reader.read(&mut buf);
                pos = 0;
            }
            b = buf[pos] as usize;
            pos += 1;

            if b <= i {
                break;
            }
        }

        c.coeffs[i] = c.coeffs[b];
        c.coeffs[b] = if (signs & 1) != 0 { -1 } else { 1 };
        signs >>= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_a() {
        let rho = [0u8; 32];
        let _mat = expand_a::<4, 4>(&rho);
    }

    #[test]
    fn test_challenge() {
        let seed = [0u8; 32];
        let mut c = Poly::new();
        challenge::<39>(&mut c, &seed);

        let mut count = 0;
        for i in 0..N {
            if c.coeffs[i] != 0 {
                count += 1;
                assert!(c.coeffs[i] == 1 || c.coeffs[i] == -1);
            }
        }
        assert_eq!(count, 39);
    }
}
