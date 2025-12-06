use super::compress::{compress, decompress};
use super::params::{N, Q};
use super::poly::Poly;
use super::polyvec::PolyVec;

fn normalize(a: i16) -> u16 {
    let mut t = a;
    t = t.wrapping_add((t >> 15) & Q);
    t = t.wrapping_sub(Q);
    t = t.wrapping_add((t >> 15) & Q);
    t as u16
}

pub fn poly_to_bytes(p: &Poly, out: &mut [u8]) {
    for i in 0..N / 2 {
        let t0 = normalize(p.coeffs[2 * i]);
        let t1 = normalize(p.coeffs[2 * i + 1]);
        out[3 * i] = t0 as u8;
        out[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        out[3 * i + 2] = (t1 >> 4) as u8;
    }
}

pub fn poly_from_bytes(p: &mut Poly, bytes: &[u8]) {
    for i in 0..N / 2 {
        p.coeffs[2 * i] = (bytes[3 * i] as i16) | (((bytes[3 * i + 1] as i16) & 0x0F) << 8);
        p.coeffs[2 * i + 1] = ((bytes[3 * i + 1] >> 4) as i16) | ((bytes[3 * i + 2] as i16) << 4);
    }
}

pub fn polyvec_to_bytes<const K: usize>(pv: &PolyVec<K>, out: &mut [u8]) {
    for i in 0..K {
        poly_to_bytes(&pv.vec[i], &mut out[i * 384..(i + 1) * 384]);
    }
}

pub fn polyvec_from_bytes<const K: usize>(pv: &mut PolyVec<K>, bytes: &[u8]) {
    for i in 0..K {
        poly_from_bytes(&mut pv.vec[i], &bytes[i * 384..(i + 1) * 384]);
    }
}

pub fn poly_compress<const D: usize>(p: &Poly, out: &mut [u8]) {
    if D == 4 {
        for i in 0..N / 2 {
            let t0 = compress::<4>(p.coeffs[2 * i]) as u8;
            let t1 = compress::<4>(p.coeffs[2 * i + 1]) as u8;
            out[i] = t0 | (t1 << 4);
        }
    } else if D == 5 {
        for i in 0..N / 8 {
            let mut t = [0u8; 8];
            for j in 0..8 {
                t[j] = compress::<5>(p.coeffs[8 * i + j]) as u8;
            }
            out[5 * i] = t[0] | (t[1] << 5);
            out[5 * i + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
            out[5 * i + 2] = (t[3] >> 1) | (t[4] << 4);
            out[5 * i + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
            out[5 * i + 4] = (t[6] >> 2) | (t[7] << 3);
        }
    }
}

pub fn poly_decompress<const D: usize>(p: &mut Poly, bytes: &[u8]) {
    if D == 4 {
        for i in 0..N / 2 {
            p.coeffs[2 * i] = decompress::<4>((bytes[i] & 0x0F) as u16);
            p.coeffs[2 * i + 1] = decompress::<4>((bytes[i] >> 4) as u16);
        }
    } else if D == 5 {
        for i in 0..N / 8 {
            let t0 = bytes[5 * i];
            let t1 = bytes[5 * i + 1];
            let t2 = bytes[5 * i + 2];
            let t3 = bytes[5 * i + 3];
            let t4 = bytes[5 * i + 4];

            p.coeffs[8 * i] = decompress::<5>((t0 & 0x1F) as u16);
            p.coeffs[8 * i + 1] = decompress::<5>(((t0 >> 5) | (t1 << 3)) as u16 & 0x1F);
            p.coeffs[8 * i + 2] = decompress::<5>(((t1 >> 2) & 0x1F) as u16);
            p.coeffs[8 * i + 3] = decompress::<5>(((t1 >> 7) | (t2 << 1)) as u16 & 0x1F);
            p.coeffs[8 * i + 4] = decompress::<5>(((t2 >> 4) | (t3 << 4)) as u16 & 0x1F);
            p.coeffs[8 * i + 5] = decompress::<5>(((t3 >> 1) & 0x1F) as u16);
            p.coeffs[8 * i + 6] = decompress::<5>(((t3 >> 6) | (t4 << 2)) as u16 & 0x1F);
            p.coeffs[8 * i + 7] = decompress::<5>((t4 >> 3) as u16);
        }
    }
}

pub fn polyvec_compress<const K: usize, const DU: usize>(pv: &PolyVec<K>, out: &mut [u8]) {
    if DU == 10 {
        for i in 0..K {
            for j in 0..N / 4 {
                let mut t = [0u16; 4];
                for k in 0..4 {
                    t[k] = compress::<10>(pv.vec[i].coeffs[4 * j + k]);
                }
                let off = i * 320 + 5 * j;
                out[off] = t[0] as u8;
                out[off + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                out[off + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                out[off + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                out[off + 4] = (t[3] >> 2) as u8;
            }
        }
    } else if DU == 11 {
        for i in 0..K {
            for j in 0..N / 8 {
                let mut t = [0u16; 8];
                for k in 0..8 {
                    t[k] = compress::<11>(pv.vec[i].coeffs[8 * j + k]);
                }
                let off = i * 352 + 11 * j;
                out[off] = t[0] as u8;
                out[off + 1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
                out[off + 2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
                out[off + 3] = (t[2] >> 2) as u8;
                out[off + 4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
                out[off + 5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
                out[off + 6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
                out[off + 7] = (t[5] >> 1) as u8;
                out[off + 8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
                out[off + 9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
                out[off + 10] = (t[7] >> 3) as u8;
            }
        }
    }
}

pub fn polyvec_decompress<const K: usize, const DU: usize>(pv: &mut PolyVec<K>, bytes: &[u8]) {
    if DU == 10 {
        for i in 0..K {
            for j in 0..N / 4 {
                let off = i * 320 + 5 * j;
                let t0 = bytes[off] as u16 | ((bytes[off + 1] as u16) << 8);
                let t1 = (bytes[off + 1] as u16 >> 2) | ((bytes[off + 2] as u16) << 6);
                let t2 = (bytes[off + 2] as u16 >> 4) | ((bytes[off + 3] as u16) << 4);
                let t3 = (bytes[off + 3] as u16 >> 6) | ((bytes[off + 4] as u16) << 2);

                pv.vec[i].coeffs[4 * j] = decompress::<10>(t0 & 0x3FF);
                pv.vec[i].coeffs[4 * j + 1] = decompress::<10>(t1 & 0x3FF);
                pv.vec[i].coeffs[4 * j + 2] = decompress::<10>(t2 & 0x3FF);
                pv.vec[i].coeffs[4 * j + 3] = decompress::<10>(t3 & 0x3FF);
            }
        }
    } else if DU == 11 {
        for i in 0..K {
            for j in 0..N / 8 {
                let off = i * 352 + 11 * j;
                let b = &bytes[off..off + 11];

                let t0 = b[0] as u16 | ((b[1] as u16) << 8);
                let t1 = (b[1] as u16 >> 3) | ((b[2] as u16) << 5);
                let t2 = (b[2] as u16 >> 6) | ((b[3] as u16) << 2) | ((b[4] as u16) << 10);
                let t3 = (b[4] as u16 >> 1) | ((b[5] as u16) << 7);
                let t4 = (b[5] as u16 >> 4) | ((b[6] as u16) << 4);
                let t5 = (b[6] as u16 >> 7) | ((b[7] as u16) << 1) | ((b[8] as u16) << 9);
                let t6 = (b[8] as u16 >> 2) | ((b[9] as u16) << 6);
                let t7 = (b[9] as u16 >> 5) | ((b[10] as u16) << 3);

                pv.vec[i].coeffs[8 * j] = decompress::<11>(t0 & 0x7FF);
                pv.vec[i].coeffs[8 * j + 1] = decompress::<11>(t1 & 0x7FF);
                pv.vec[i].coeffs[8 * j + 2] = decompress::<11>(t2 & 0x7FF);
                pv.vec[i].coeffs[8 * j + 3] = decompress::<11>(t3 & 0x7FF);
                pv.vec[i].coeffs[8 * j + 4] = decompress::<11>(t4 & 0x7FF);
                pv.vec[i].coeffs[8 * j + 5] = decompress::<11>(t5 & 0x7FF);
                pv.vec[i].coeffs[8 * j + 6] = decompress::<11>(t6 & 0x7FF);
                pv.vec[i].coeffs[8 * j + 7] = decompress::<11>(t7 & 0x7FF);
            }
        }
    }
}

pub fn poly_to_msg(p: &Poly, msg: &mut [u8; 32]) {
    for i in 0..N / 8 {
        msg[i] = 0;
        for j in 0..8 {
            let t = compress::<1>(p.coeffs[8 * i + j]) as u8;
            msg[i] |= t << j;
        }
    }
}

pub fn poly_from_msg(p: &mut Poly, msg: &[u8; 32]) {
    for i in 0..N / 8 {
        for j in 0..8 {
            let mask = ((msg[i] >> j) & 1) as u16;
            p.coeffs[8 * i + j] = decompress::<1>(mask);
        }
    }
}
