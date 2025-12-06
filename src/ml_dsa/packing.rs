use crate::ml_dsa::params::N;
use crate::ml_dsa::poly::Poly;
use crate::ml_dsa::polyvec::PolyVec;

pub fn pack_pk<const K: usize>(pk: &mut [u8], rho: &[u8; 32], t1: &PolyVec<K>) {
    pk[..32].copy_from_slice(rho);
    let mut pos = 32;

    for i in 0..K {
        for j in 0..N {
            let a = t1.vec[i].coeffs[j] as u32;
            pk[pos] = a as u8;
            pk[pos + 1] = (a >> 8) as u8;
            pk[pos + 2] = (a >> 16) as u8;
            pk[pos + 3] = (a >> 24) as u8;
            pos += 4;
        }
    }
}

pub fn unpack_pk<const K: usize>(rho: &mut [u8; 32], t1: &mut PolyVec<K>, pk: &[u8]) {
    rho.copy_from_slice(&pk[..32]);
    let mut pos = 32;

    for i in 0..K {
        for j in 0..N {
            t1.vec[i].coeffs[j] = (pk[pos] as u32
                | ((pk[pos + 1] as u32) << 8)
                | ((pk[pos + 2] as u32) << 16)
                | ((pk[pos + 3] as u32) << 24)) as i32;
            pos += 4;
        }
    }
}

pub fn polyt1_pack(r: &mut [u8], a: &Poly) {
    for i in 0..N / 4 {
        r[5 * i] = a.coeffs[4 * i] as u8;
        r[5 * i + 1] = ((a.coeffs[4 * i] >> 8) | (a.coeffs[4 * i + 1] << 2)) as u8;
        r[5 * i + 2] = ((a.coeffs[4 * i + 1] >> 6) | (a.coeffs[4 * i + 2] << 4)) as u8;
        r[5 * i + 3] = ((a.coeffs[4 * i + 2] >> 4) | (a.coeffs[4 * i + 3] << 6)) as u8;
        r[5 * i + 4] = (a.coeffs[4 * i + 3] >> 2) as u8;
    }
}

pub fn polyt1_unpack(r: &mut Poly, a: &[u8]) {
    for i in 0..N / 4 {
        r.coeffs[4 * i] = ((a[5 * i] as i32) | ((a[5 * i + 1] as i32) << 8)) & 0x3FF;
        r.coeffs[4 * i + 1] = (((a[5 * i + 1] as i32) >> 2) | ((a[5 * i + 2] as i32) << 6)) & 0x3FF;
        r.coeffs[4 * i + 2] = (((a[5 * i + 2] as i32) >> 4) | ((a[5 * i + 3] as i32) << 4)) & 0x3FF;
        r.coeffs[4 * i + 3] = (((a[5 * i + 3] as i32) >> 6) | ((a[5 * i + 4] as i32) << 2)) & 0x3FF;
    }
}

pub fn polyt0_pack(r: &mut [u8], a: &Poly) {
    const D: i32 = 1 << 12;
    let mut t = [0i32; 8];

    for i in 0..N / 8 {
        t[0] = D - a.coeffs[8 * i];
        t[1] = D - a.coeffs[8 * i + 1];
        t[2] = D - a.coeffs[8 * i + 2];
        t[3] = D - a.coeffs[8 * i + 3];
        t[4] = D - a.coeffs[8 * i + 4];
        t[5] = D - a.coeffs[8 * i + 5];
        t[6] = D - a.coeffs[8 * i + 6];
        t[7] = D - a.coeffs[8 * i + 7];

        r[13 * i] = t[0] as u8;
        r[13 * i + 1] = (t[0] >> 8) as u8;
        r[13 * i + 1] |= (t[1] << 5) as u8;
        r[13 * i + 2] = (t[1] >> 3) as u8;
        r[13 * i + 3] = (t[1] >> 11) as u8;
        r[13 * i + 3] |= (t[2] << 2) as u8;
        r[13 * i + 4] = (t[2] >> 6) as u8;
        r[13 * i + 4] |= (t[3] << 7) as u8;
        r[13 * i + 5] = (t[3] >> 1) as u8;
        r[13 * i + 6] = (t[3] >> 9) as u8;
        r[13 * i + 6] |= (t[4] << 4) as u8;
        r[13 * i + 7] = (t[4] >> 4) as u8;
        r[13 * i + 8] = (t[4] >> 12) as u8;
        r[13 * i + 8] |= (t[5] << 1) as u8;
        r[13 * i + 9] = (t[5] >> 7) as u8;
        r[13 * i + 9] |= (t[6] << 6) as u8;
        r[13 * i + 10] = (t[6] >> 2) as u8;
        r[13 * i + 11] = (t[6] >> 10) as u8;
        r[13 * i + 11] |= (t[7] << 3) as u8;
        r[13 * i + 12] = (t[7] >> 5) as u8;
    }
}

pub fn polyt0_unpack(r: &mut Poly, a: &[u8]) {
    const D: i32 = 1 << 12;

    for i in 0..N / 8 {
        r.coeffs[8 * i] = a[13 * i] as i32;
        r.coeffs[8 * i] |= (a[13 * i + 1] as i32) << 8;
        r.coeffs[8 * i] &= 0x1FFF;

        r.coeffs[8 * i + 1] = (a[13 * i + 1] as i32) >> 5;
        r.coeffs[8 * i + 1] |= (a[13 * i + 2] as i32) << 3;
        r.coeffs[8 * i + 1] |= (a[13 * i + 3] as i32) << 11;
        r.coeffs[8 * i + 1] &= 0x1FFF;

        r.coeffs[8 * i + 2] = (a[13 * i + 3] as i32) >> 2;
        r.coeffs[8 * i + 2] |= (a[13 * i + 4] as i32) << 6;
        r.coeffs[8 * i + 2] &= 0x1FFF;

        r.coeffs[8 * i + 3] = (a[13 * i + 4] as i32) >> 7;
        r.coeffs[8 * i + 3] |= (a[13 * i + 5] as i32) << 1;
        r.coeffs[8 * i + 3] |= (a[13 * i + 6] as i32) << 9;
        r.coeffs[8 * i + 3] &= 0x1FFF;

        r.coeffs[8 * i + 4] = (a[13 * i + 6] as i32) >> 4;
        r.coeffs[8 * i + 4] |= (a[13 * i + 7] as i32) << 4;
        r.coeffs[8 * i + 4] |= (a[13 * i + 8] as i32) << 12;
        r.coeffs[8 * i + 4] &= 0x1FFF;

        r.coeffs[8 * i + 5] = (a[13 * i + 8] as i32) >> 1;
        r.coeffs[8 * i + 5] |= (a[13 * i + 9] as i32) << 7;
        r.coeffs[8 * i + 5] &= 0x1FFF;

        r.coeffs[8 * i + 6] = (a[13 * i + 9] as i32) >> 6;
        r.coeffs[8 * i + 6] |= (a[13 * i + 10] as i32) << 2;
        r.coeffs[8 * i + 6] |= (a[13 * i + 11] as i32) << 10;
        r.coeffs[8 * i + 6] &= 0x1FFF;

        r.coeffs[8 * i + 7] = (a[13 * i + 11] as i32) >> 3;
        r.coeffs[8 * i + 7] |= (a[13 * i + 12] as i32) << 5;
        r.coeffs[8 * i + 7] &= 0x1FFF;

        r.coeffs[8 * i] = D - r.coeffs[8 * i];
        r.coeffs[8 * i + 1] = D - r.coeffs[8 * i + 1];
        r.coeffs[8 * i + 2] = D - r.coeffs[8 * i + 2];
        r.coeffs[8 * i + 3] = D - r.coeffs[8 * i + 3];
        r.coeffs[8 * i + 4] = D - r.coeffs[8 * i + 4];
        r.coeffs[8 * i + 5] = D - r.coeffs[8 * i + 5];
        r.coeffs[8 * i + 6] = D - r.coeffs[8 * i + 6];
        r.coeffs[8 * i + 7] = D - r.coeffs[8 * i + 7];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polyt1_pack_unpack() {
        let mut a = Poly::new();
        for i in 0..N {
            a.coeffs[i] = (i % 1024) as i32;
        }

        let mut packed = [0u8; 320];
        polyt1_pack(&mut packed, &a);

        let mut b = Poly::new();
        polyt1_unpack(&mut b, &packed);

        for i in 0..N {
            assert_eq!(a.coeffs[i], b.coeffs[i]);
        }
    }

    #[test]
    fn test_polyt0_pack_unpack() {
        let mut a = Poly::new();
        for i in 0..N {
            a.coeffs[i] = (i as i32 % 8192) - 4095;
        }

        let mut packed = [0u8; 416];
        polyt0_pack(&mut packed, &a);

        let mut b = Poly::new();
        polyt0_unpack(&mut b, &packed);

        for i in 0..N {
            assert_eq!(a.coeffs[i], b.coeffs[i]);
        }
    }
}
