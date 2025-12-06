use crate::encode::{
    poly_compress, poly_decompress, poly_from_msg, poly_to_msg, polyvec_compress,
    polyvec_decompress, polyvec_from_bytes, polyvec_to_bytes,
};
use crate::ntt;
use crate::params::{N, POLYBYTES, SYMBYTES};
use crate::poly::Poly;
use crate::polyvec::PolyVec;
use crate::sampling::{sample_poly_cbd_eta1, sample_poly_cbd_eta2, sample_uniform};
use crate::symmetric::hash_g;

fn gen_matrix<const K: usize>(a: &mut [[Poly; K]; K], seed: &[u8], transposed: bool) {
    for i in 0..K {
        for j in 0..K {
            if transposed {
                sample_uniform(&mut a[i][j], seed, i as u8, j as u8);
            } else {
                sample_uniform(&mut a[i][j], seed, j as u8, i as u8);
            }
        }
    }
}

pub fn keypair<const K: usize, const ETA1: usize>(
    pk: &mut [u8],
    sk: &mut [u8],
    seed: &[u8; SYMBYTES],
) {
    let buf = hash_g(seed);
    let (publicseed, noiseseed) = buf.split_at(SYMBYTES);

    let mut a: [[Poly; K]; K] = core::array::from_fn(|_| core::array::from_fn(|_| Poly::new()));
    gen_matrix::<K>(&mut a, publicseed, false);

    let mut skpv: PolyVec<K> = PolyVec::new();
    let mut e: PolyVec<K> = PolyVec::new();

    let mut nonce = 0u8;
    for i in 0..K {
        sample_poly_cbd_eta1::<ETA1>(&mut skpv.vec[i], noiseseed.try_into().unwrap(), nonce);
        nonce += 1;
    }
    for i in 0..K {
        sample_poly_cbd_eta1::<ETA1>(&mut e.vec[i], noiseseed.try_into().unwrap(), nonce);
        nonce += 1;
    }

    skpv.ntt();
    skpv.reduce();
    e.ntt();

    let mut pkpv: PolyVec<K> = PolyVec::new();
    for i in 0..K {
        let mut t = Poly::new();
        for j in 0..K {
            let tmp = ntt::basemul(&a[i][j], &skpv.vec[j]);
            t.add(&tmp);
        }
        t.reduce();
        t.montgomery_reduce_coeffs();
        pkpv.vec[i] = t;
    }

    pkpv.add(&e);
    pkpv.reduce();

    polyvec_to_bytes::<K>(&pkpv, pk);
    pk[K * POLYBYTES..K * POLYBYTES + SYMBYTES].copy_from_slice(publicseed);

    polyvec_to_bytes::<K>(&skpv, sk);
}

pub fn enc<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    ct: &mut [u8],
    msg: &[u8; SYMBYTES],
    pk: &[u8],
    coins: &[u8; SYMBYTES],
) {
    let mut pkpv: PolyVec<K> = PolyVec::new();
    polyvec_from_bytes::<K>(&mut pkpv, &pk[..K * POLYBYTES]);

    let seed = &pk[K * POLYBYTES..K * POLYBYTES + SYMBYTES];

    let mut at: [[Poly; K]; K] = core::array::from_fn(|_| core::array::from_fn(|_| Poly::new()));
    gen_matrix::<K>(&mut at, seed, true);

    let mut sp: PolyVec<K> = PolyVec::new();
    let mut ep: PolyVec<K> = PolyVec::new();
    let mut epp = Poly::new();

    let mut nonce = 0u8;
    for i in 0..K {
        sample_poly_cbd_eta1::<ETA1>(&mut sp.vec[i], coins, nonce);
        nonce += 1;
    }
    for i in 0..K {
        sample_poly_cbd_eta2(&mut ep.vec[i], coins, nonce);
        nonce += 1;
    }
    sample_poly_cbd_eta2(&mut epp, coins, nonce);

    sp.ntt();
    sp.reduce();

    let mut u: PolyVec<K> = PolyVec::new();
    for i in 0..K {
        let mut t = Poly::new();
        for j in 0..K {
            let tmp = ntt::basemul(&at[i][j], &sp.vec[j]);
            t.add(&tmp);
        }
        t.reduce();
        u.vec[i] = t;
    }

    let mut v = pkpv.pointwise_acc_montgomery(&sp);

    u.inv_ntt();
    ntt::inv_ntt(&mut v);

    u.add(&ep);
    u.reduce();

    let mut k = Poly::new();
    poly_from_msg(&mut k, msg);
    v.add(&epp);
    v.add(&k);
    v.reduce();

    u.cond_sub_q();
    v.cond_sub_q();

    let u_bytes = K * N * DU / 8;
    polyvec_compress::<K, DU>(&u, &mut ct[..u_bytes]);
    poly_compress::<DV>(&v, &mut ct[u_bytes..]);
}

pub fn dec<const K: usize, const DU: usize, const DV: usize>(
    msg: &mut [u8; SYMBYTES],
    ct: &[u8],
    sk: &[u8],
) {
    let mut u: PolyVec<K> = PolyVec::new();
    let mut v = Poly::new();

    let u_bytes = K * N * DU / 8;
    polyvec_decompress::<K, DU>(&mut u, &ct[..u_bytes]);
    poly_decompress::<DV>(&mut v, &ct[u_bytes..]);

    let mut skpv: PolyVec<K> = PolyVec::new();
    polyvec_from_bytes::<K>(&mut skpv, sk);

    u.ntt();
    let mut mp = skpv.pointwise_acc_montgomery(&u);
    ntt::inv_ntt(&mut mp);

    v.sub(&mp);
    v.reduce();
    v.cond_sub_q();

    poly_to_msg(&v, msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indcpa_roundtrip_768() {
        let seed = [0u8; 32];
        let coins = [1u8; 32];
        let msg = [2u8; 32];

        let mut pk = [0u8; crate::params::mlkem768::PUBLICKEYBYTES];
        let mut sk = [0u8; 3 * POLYBYTES];
        keypair::<3, 2>(&mut pk, &mut sk, &seed);

        let mut ct = [0u8; crate::params::mlkem768::CIPHERTEXTBYTES];
        enc::<3, 2, 2, 10, 4>(&mut ct, &msg, &pk, &coins);

        let mut dec_msg = [0u8; 32];
        dec::<3, 10, 4>(&mut dec_msg, &ct, &sk);

        assert_eq!(msg, dec_msg);
    }
}
