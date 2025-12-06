use crate::params::{N, Q};
use crate::poly::Poly;
use crate::symmetric::{PrfState, XofState};

const REJ_UNIFORM_BUFLEN: usize = 504;

pub fn sample_uniform(poly: &mut Poly, seed: &[u8], i: u8, j: u8) {
    let mut xof = XofState::new(seed, i, j);
    let mut buf = [0u8; REJ_UNIFORM_BUFLEN];
    xof.squeeze(&mut buf);

    let mut ctr = 0usize;
    let mut pos = 0usize;

    while ctr < N && pos + 3 <= REJ_UNIFORM_BUFLEN {
        let d1 = ((buf[pos] as u16) | ((buf[pos + 1] as u16) << 8)) & 0x0FFF;
        let d2 = (((buf[pos + 1] as u16) >> 4) | ((buf[pos + 2] as u16) << 4)) & 0x0FFF;
        pos += 3;

        if d1 < Q as u16 {
            poly.coeffs[ctr] = d1 as i16;
            ctr += 1;
        }
        if ctr < N && d2 < Q as u16 {
            poly.coeffs[ctr] = d2 as i16;
            ctr += 1;
        }
    }

    while ctr < N {
        let mut off = [0u8; 3];
        xof.squeeze(&mut off);

        let d1 = ((off[0] as u16) | ((off[1] as u16) << 8)) & 0x0FFF;
        let d2 = (((off[1] as u16) >> 4) | ((off[2] as u16) << 4)) & 0x0FFF;

        if d1 < Q as u16 {
            poly.coeffs[ctr] = d1 as i16;
            ctr += 1;
        }
        if ctr < N && d2 < Q as u16 {
            poly.coeffs[ctr] = d2 as i16;
            ctr += 1;
        }
    }
}

fn load32_le(x: &[u8]) -> u32 {
    (x[0] as u32) | ((x[1] as u32) << 8) | ((x[2] as u32) << 16) | ((x[3] as u32) << 24)
}

fn cbd2(poly: &mut Poly, buf: &[u8]) {
    for i in 0..N / 8 {
        let t = load32_le(&buf[4 * i..]);
        let mut d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            poly.coeffs[8 * i + j] = a - b;
        }
    }
}

fn load24_le(x: &[u8]) -> u32 {
    (x[0] as u32) | ((x[1] as u32) << 8) | ((x[2] as u32) << 16)
}

fn cbd3(poly: &mut Poly, buf: &[u8]) {
    for i in 0..N / 4 {
        let t = load24_le(&buf[3 * i..]);
        let mut d = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;

        for j in 0..4 {
            let a = ((d >> (6 * j)) & 0x7) as i16;
            let b = ((d >> (6 * j + 3)) & 0x7) as i16;
            poly.coeffs[4 * i + j] = a - b;
        }
    }
}

pub fn sample_poly_cbd_eta1<const ETA: usize>(poly: &mut Poly, seed: &[u8; 32], nonce: u8) {
    let mut prf = PrfState::new(seed, nonce);
    let mut buf = [0u8; 192];

    if ETA == 2 {
        prf.squeeze(&mut buf[..128]);
        cbd2(poly, &buf[..128]);
    } else if ETA == 3 {
        prf.squeeze(&mut buf[..192]);
        cbd3(poly, &buf[..192]);
    }
}

pub fn sample_poly_cbd_eta2(poly: &mut Poly, seed: &[u8; 32], nonce: u8) {
    let mut prf = PrfState::new(seed, nonce);
    let mut buf = [0u8; 128];
    prf.squeeze(&mut buf);
    cbd2(poly, &buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbd2_range() {
        let mut poly = Poly::new();
        let buf = [0u8; 128];
        cbd2(&mut poly, &buf);
        for coeff in poly.coeffs.iter() {
            assert!(*coeff >= -2 && *coeff <= 2);
        }
    }

    #[test]
    fn test_cbd3_range() {
        let mut poly = Poly::new();
        let buf = [0u8; 192];
        cbd3(&mut poly, &buf);
        for coeff in poly.coeffs.iter() {
            assert!(*coeff >= -3 && *coeff <= 3);
        }
    }
}
