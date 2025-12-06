use super::error::Error;
use super::packing::{polyt0_pack, polyt1_pack};
use super::params::{Params, SEEDBYTES, TRBYTES};
use super::poly::Poly;
use super::polyvec::{polyvec_matrix_pointwise_montgomery, PolyVec};
use super::rounding::{highbits, power2round, use_hint};
use super::sampling::{challenge, expand_a};
use super::symmetric::{crh, shake256_64, shake256_into};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, Zeroizing};

macro_rules! impl_dsa {
    ($mod_name:ident, $params:ty) => {
        pub mod $mod_name {
            use super::*;

            pub const PUBLIC_KEY_BYTES: usize = <$params>::CRYPTO_PUBLICKEYBYTES;
            pub const SECRET_KEY_BYTES: usize = <$params>::CRYPTO_SECRETKEYBYTES;
            pub const SIGNATURE_BYTES: usize = <$params>::CRYPTO_BYTES;

            const K: usize = <$params>::K;
            const L: usize = <$params>::L;
            const ETA: usize = <$params>::ETA;
            const TAU: usize = <$params>::TAU;
            const BETA: usize = <$params>::BETA;
            const GAMMA1: usize = <$params>::GAMMA1;
            const GAMMA2: usize = <$params>::GAMMA2;
            const OMEGA: usize = <$params>::OMEGA;

            const POLYT1_PACKEDBYTES: usize = <$params>::POLYT1_PACKEDBYTES;
            const POLYT0_PACKEDBYTES: usize = <$params>::POLYT0_PACKEDBYTES;
            const POLYZ_PACKEDBYTES: usize = <$params>::POLYZ_PACKEDBYTES;
            const POLYETA_PACKEDBYTES: usize = <$params>::POLYETA_PACKEDBYTES;

            #[derive(Clone)]
            pub struct PublicKey {
                bytes: [u8; PUBLIC_KEY_BYTES],
            }

            impl PublicKey {
                pub fn as_bytes(&self) -> &[u8] {
                    &self.bytes
                }

                pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                    if bytes.len() != PUBLIC_KEY_BYTES {
                        return Err(Error::InvalidPublicKeyLength);
                    }
                    let mut pk = Self {
                        bytes: [0u8; PUBLIC_KEY_BYTES],
                    };
                    pk.bytes.copy_from_slice(bytes);
                    Ok(pk)
                }
            }

            #[derive(Clone)]
            pub struct SecretKey {
                bytes: [u8; SECRET_KEY_BYTES],
            }

            impl Zeroize for SecretKey {
                fn zeroize(&mut self) {
                    self.bytes.zeroize();
                }
            }

            impl Drop for SecretKey {
                fn drop(&mut self) {
                    self.zeroize();
                }
            }

            impl SecretKey {
                pub fn as_bytes(&self) -> &[u8] {
                    &self.bytes
                }

                pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                    if bytes.len() != SECRET_KEY_BYTES {
                        return Err(Error::InvalidSecretKeyLength);
                    }
                    let mut sk = Self {
                        bytes: [0u8; SECRET_KEY_BYTES],
                    };
                    sk.bytes.copy_from_slice(bytes);
                    Ok(sk)
                }
            }

            #[derive(Clone)]
            pub struct Signature {
                bytes: [u8; SIGNATURE_BYTES],
            }

            impl Signature {
                pub fn as_bytes(&self) -> &[u8] {
                    &self.bytes
                }

                pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                    if bytes.len() != SIGNATURE_BYTES {
                        return Err(Error::InvalidSignatureLength);
                    }
                    let mut sig = Self {
                        bytes: [0u8; SIGNATURE_BYTES],
                    };
                    sig.bytes.copy_from_slice(bytes);
                    Ok(sig)
                }
            }

            pub fn generate(rng: &mut impl CryptoRngCore) -> (PublicKey, SecretKey) {
                let mut seed = [0u8; SEEDBYTES];
                rng.fill_bytes(&mut seed);
                generate_deterministic(&seed)
            }

            pub fn generate_deterministic(seed: &[u8; 32]) -> (PublicKey, SecretKey) {
                let mut pk = PublicKey {
                    bytes: [0u8; PUBLIC_KEY_BYTES],
                };
                let mut sk = SecretKey {
                    bytes: [0u8; SECRET_KEY_BYTES],
                };

                let expanded = shake256_64(seed);
                let rho = &expanded[0..32];
                let rhoprime = &expanded[32..64];
                let mut key = [0u8; 32];
                let mut key_input = [0u8; 65];
                key_input[0] = K as u8;
                key_input[1..33].copy_from_slice(rho);
                key_input[33..65].copy_from_slice(rhoprime);
                let key_hash = shake256_64(&key_input);
                key.copy_from_slice(&key_hash[..32]);

                let mat = expand_a::<K, L>(rho.try_into().unwrap());

                let mut s1 = PolyVec::<L>::new();
                let mut s2 = PolyVec::<K>::new();

                let mut rhoprime_arr = [0u8; 64];
                rhoprime_arr[..32].copy_from_slice(rhoprime);
                s1.uniform_eta::<ETA>(&rhoprime_arr, 0);
                s2.uniform_eta::<ETA>(&rhoprime_arr, L as u16);

                let mut s1hat = s1.clone();
                s1hat.ntt();

                let mut t = polyvec_matrix_pointwise_montgomery(&mat, &s1hat);
                t.invntt_tomont();
                t.add(&s2);
                t.reduce();
                t.freeze();

                let mut t1 = PolyVec::<K>::new();
                let mut t0 = PolyVec::<K>::new();

                for i in 0..K {
                    for j in 0..super::super::params::N {
                        let (a1, a0) = power2round(t.vec[i].coeffs[j]);
                        t1.vec[i].coeffs[j] = a1;
                        t0.vec[i].coeffs[j] = a0;
                    }
                }

                pk.bytes[..32].copy_from_slice(rho);
                let mut pos = 32;
                for i in 0..K {
                    polyt1_pack(&mut pk.bytes[pos..pos + POLYT1_PACKEDBYTES], &t1.vec[i]);
                    pos += POLYT1_PACKEDBYTES;
                }

                let mut tr = [0u8; TRBYTES];
                crh(&mut tr, &pk.bytes);

                let mut pos = 0;
                sk.bytes[pos..pos + 32].copy_from_slice(rho);
                pos += 32;
                sk.bytes[pos..pos + 32].copy_from_slice(&key);
                pos += 32;
                sk.bytes[pos..pos + 64].copy_from_slice(&tr);
                pos += 64;

                for i in 0..L {
                    pack_poly_eta::<ETA>(&mut sk.bytes[pos..pos + POLYETA_PACKEDBYTES], &s1.vec[i]);
                    pos += POLYETA_PACKEDBYTES;
                }
                for i in 0..K {
                    pack_poly_eta::<ETA>(&mut sk.bytes[pos..pos + POLYETA_PACKEDBYTES], &s2.vec[i]);
                    pos += POLYETA_PACKEDBYTES;
                }
                for i in 0..K {
                    polyt0_pack(&mut sk.bytes[pos..pos + POLYT0_PACKEDBYTES], &t0.vec[i]);
                    pos += POLYT0_PACKEDBYTES;
                }

                (pk, sk)
            }

            pub fn sign(
                sk: &SecretKey,
                msg: &[u8],
                ctx: &[u8],
                rng: &mut impl CryptoRngCore,
            ) -> Result<Signature, Error> {
                if ctx.len() > 255 {
                    return Err(Error::InvalidContextLength);
                }

                let mut rnd = [0u8; 32];
                rng.fill_bytes(&mut rnd);

                sign_internal(sk, msg, ctx, Some(&rnd))
            }

            pub fn sign_deterministic(
                sk: &SecretKey,
                msg: &[u8],
                ctx: &[u8],
            ) -> Result<Signature, Error> {
                if ctx.len() > 255 {
                    return Err(Error::InvalidContextLength);
                }

                sign_internal(sk, msg, ctx, None)
            }

            fn sign_internal(
                sk: &SecretKey,
                msg: &[u8],
                ctx: &[u8],
                rnd: Option<&[u8; 32]>,
            ) -> Result<Signature, Error> {
                let mut sig = Signature {
                    bytes: [0u8; SIGNATURE_BYTES],
                };

                let rho = &sk.bytes[0..32];
                let key = &sk.bytes[32..64];
                let tr = &sk.bytes[64..128];

                let mut msg_prime = Zeroizing::new([0u8; 256]);
                msg_prime[0] = 0;
                msg_prime[1] = ctx.len() as u8;
                msg_prime[2..2 + ctx.len()].copy_from_slice(ctx);
                let msg_start = 2 + ctx.len();
                let msg_len = msg.len().min(256 - msg_start);
                msg_prime[msg_start..msg_start + msg_len].copy_from_slice(&msg[..msg_len]);

                let mut mu = [0u8; 64];
                let mut mu_input = [0u8; 128 + 256];
                mu_input[..64].copy_from_slice(tr);
                mu_input[64..64 + msg_start + msg_len]
                    .copy_from_slice(&msg_prime[..msg_start + msg_len]);
                shake256_into(&mu_input[..64 + msg_start + msg_len], &mut mu);

                let rnd_bytes = rnd.unwrap_or(&[0u8; 32]);
                let mut rhoprime = [0u8; 64];
                let mut rhoprime_input = [0u8; 128];
                rhoprime_input[..32].copy_from_slice(key);
                rhoprime_input[32..64].copy_from_slice(rnd_bytes);
                rhoprime_input[64..128].copy_from_slice(&mu);
                shake256_into(&rhoprime_input, &mut rhoprime);

                let mat = expand_a::<K, L>(rho.try_into().unwrap());

                let mut s1 = PolyVec::<L>::new();
                let mut s2 = PolyVec::<K>::new();
                let mut t0 = PolyVec::<K>::new();

                let mut pos = 128;
                for i in 0..L {
                    unpack_poly_eta::<ETA>(
                        &mut s1.vec[i],
                        &sk.bytes[pos..pos + POLYETA_PACKEDBYTES],
                    );
                    pos += POLYETA_PACKEDBYTES;
                }
                for i in 0..K {
                    unpack_poly_eta::<ETA>(
                        &mut s2.vec[i],
                        &sk.bytes[pos..pos + POLYETA_PACKEDBYTES],
                    );
                    pos += POLYETA_PACKEDBYTES;
                }
                for i in 0..K {
                    super::super::packing::polyt0_unpack(
                        &mut t0.vec[i],
                        &sk.bytes[pos..pos + POLYT0_PACKEDBYTES],
                    );
                    pos += POLYT0_PACKEDBYTES;
                }

                let mut s1hat = s1.clone();
                let mut s2hat = s2.clone();
                let mut t0hat = t0.clone();
                s1hat.ntt();
                s2hat.ntt();
                t0hat.ntt();
                let s1hat = s1hat.to_mont();
                let s2hat = s2hat.to_mont();
                let t0hat = t0hat.to_mont();

                let mut nonce = 0u16;
                let mut attempt = 0u32;

                loop {
                    attempt += 1;

                    if attempt > 1000 {
                        panic!("ML-DSA signing failed after 1000 attempts - likely a bug");
                    }

                    let mut y = PolyVec::<L>::new();
                    y.uniform_gamma1::<GAMMA1>(&rhoprime, nonce);
                    nonce = nonce.wrapping_add(L as u16);

                    let mut yhat = y.clone();
                    yhat.ntt();

                    let mut w = polyvec_matrix_pointwise_montgomery(&mat, &yhat);
                    w.invntt_tomont();
                    w.reduce();
                    w.freeze();

                    let mut w1 = PolyVec::<K>::new();
                    for i in 0..K {
                        for j in 0..super::super::params::N {
                            w1.vec[i].coeffs[j] = highbits::<GAMMA2>(w.vec[i].coeffs[j]);
                        }
                    }

                    let mut w1_packed = [0u8; K * <$params>::POLYW1_PACKEDBYTES];
                    for i in 0..K {
                        pack_w1::<GAMMA2>(
                            &mut w1_packed[i * <$params>::POLYW1_PACKEDBYTES
                                ..(i + 1) * <$params>::POLYW1_PACKEDBYTES],
                            &w1.vec[i],
                        );
                    }

                    let mut c_input = [0u8; 64 + K * <$params>::POLYW1_PACKEDBYTES];
                    c_input[..64].copy_from_slice(&mu);
                    c_input[64..].copy_from_slice(&w1_packed);
                    let c_hash = shake256_64(&c_input);

                    let mut c = Poly::new();
                    challenge::<TAU>(&mut c, c_hash[..32].try_into().unwrap());

                    let mut chat = c.clone();
                    chat.ntt();

                    let mut z = PolyVec::<L>::new();
                    for i in 0..L {
                        z.vec[i] = Poly::pointwise_montgomery(&chat, &s1hat.vec[i]);
                    }
                    z.invntt_tomont();
                    z.add(&y);
                    z.reduce();

                    if z.chknorm((GAMMA1 - BETA) as i32) {
                        continue;
                    }

                    let mut cs2 = PolyVec::<K>::new();
                    for i in 0..K {
                        cs2.vec[i] = Poly::pointwise_montgomery(&chat, &s2hat.vec[i]);
                    }
                    cs2.invntt_tomont();
                    cs2.reduce();

                    let mut w_minus_cs2 = w.clone();
                    for i in 0..K {
                        for j in 0..super::super::params::N {
                            w_minus_cs2.vec[i].coeffs[j] -= cs2.vec[i].coeffs[j];
                        }
                    }
                    w_minus_cs2.reduce();
                    w_minus_cs2.freeze();

                    let mut r0_norm_check = false;
                    for i in 0..K {
                        for j in 0..super::super::params::N {
                            use super::super::rounding::lowbits;
                            let r0 = lowbits::<GAMMA2>(w_minus_cs2.vec[i].coeffs[j]);
                            if r0.abs() >= (GAMMA2 as i32) - (BETA as i32) {
                                r0_norm_check = true;
                                break;
                            }
                        }
                        if r0_norm_check {
                            break;
                        }
                    }

                    if r0_norm_check {
                        continue;
                    }

                    let mut ct0 = PolyVec::<K>::new();
                    for i in 0..K {
                        ct0.vec[i] = Poly::pointwise_montgomery(&chat, &t0hat.vec[i]);
                    }
                    ct0.invntt_tomont();
                    ct0.reduce();

                    if ct0.chknorm(GAMMA2 as i32) {
                        continue;
                    }

                    let mut h = [false; K * super::super::params::N];
                    let mut hint_count = 0;
                    for i in 0..K {
                        for j in 0..super::super::params::N {
                            use super::super::rounding::highbits;
                            let ct0_coeff = ct0.vec[i].coeffs[j];
                            let wcs2_coeff = w_minus_cs2.vec[i].coeffs[j];

                            let r1 = highbits::<GAMMA2>(wcs2_coeff);
                            let v1 = highbits::<GAMMA2>(wcs2_coeff + ct0_coeff);

                            if r1 != v1 {
                                h[i * super::super::params::N + j] = true;
                                hint_count += 1;
                            }
                        }
                    }

                    if hint_count > OMEGA {
                        continue;
                    }

                    sig.bytes[..32].copy_from_slice(&c_hash[..32]);
                    let mut pos = 32;
                    for i in 0..L {
                        pack_z::<GAMMA1>(&mut sig.bytes[pos..pos + POLYZ_PACKEDBYTES], &z.vec[i]);
                        pos += POLYZ_PACKEDBYTES;
                    }

                    pack_hint(&mut sig.bytes[pos..], &h, K);

                    break;
                }

                Ok(sig)
            }

            pub fn verify(
                pk: &PublicKey,
                msg: &[u8],
                ctx: &[u8],
                sig: &Signature,
            ) -> Result<(), Error> {
                if ctx.len() > 255 {
                    return Err(Error::InvalidContextLength);
                }

                let rho = &pk.bytes[0..32];
                let mut t1 = PolyVec::<K>::new();
                let mut pos = 32;
                for i in 0..K {
                    super::super::packing::polyt1_unpack(
                        &mut t1.vec[i],
                        &pk.bytes[pos..pos + POLYT1_PACKEDBYTES],
                    );
                    pos += POLYT1_PACKEDBYTES;
                }

                let c_tilde = &sig.bytes[0..32];

                let mut z = PolyVec::<L>::new();
                pos = 32;
                for i in 0..L {
                    unpack_z::<GAMMA1>(&mut z.vec[i], &sig.bytes[pos..pos + POLYZ_PACKEDBYTES])?;
                    pos += POLYZ_PACKEDBYTES;
                }

                if z.chknorm((GAMMA1 - BETA) as i32) {
                    return Err(Error::SignatureVerificationFailed);
                }

                let mut h = [false; K * super::super::params::N];
                unpack_hint(&mut h, &sig.bytes[pos..], K)?;

                let mat = expand_a::<K, L>(rho.try_into().unwrap());

                let mut msg_prime = Zeroizing::new([0u8; 256]);
                msg_prime[0] = 0;
                msg_prime[1] = ctx.len() as u8;
                msg_prime[2..2 + ctx.len()].copy_from_slice(ctx);
                let msg_start = 2 + ctx.len();
                let msg_len = msg.len().min(256 - msg_start);
                msg_prime[msg_start..msg_start + msg_len].copy_from_slice(&msg[..msg_len]);

                let mut tr = [0u8; 64];
                crh(&mut tr, &pk.bytes);

                let mut mu = [0u8; 64];
                let mut mu_input = [0u8; 128 + 256];
                mu_input[..64].copy_from_slice(&tr);
                mu_input[64..64 + msg_start + msg_len]
                    .copy_from_slice(&msg_prime[..msg_start + msg_len]);
                shake256_into(&mu_input[..64 + msg_start + msg_len], &mut mu);

                let mut c = Poly::new();
                challenge::<TAU>(&mut c, c_tilde.try_into().unwrap());

                let mut chat = c.clone();
                chat.ntt();

                let mut zhat = z.clone();
                zhat.ntt();

                let mut az = polyvec_matrix_pointwise_montgomery(&mat, &zhat);

                let mut t1_2d = t1.clone();
                for i in 0..K {
                    for j in 0..super::super::params::N {
                        t1_2d.vec[i].coeffs[j] <<= super::super::params::D;
                    }
                }
                t1_2d.ntt();
                let t1_2d = t1_2d.to_mont();

                let mut ct1 = PolyVec::<K>::new();
                for i in 0..K {
                    ct1.vec[i] = Poly::pointwise_montgomery(&chat, &t1_2d.vec[i]);
                }

                for i in 0..K {
                    for j in 0..super::super::params::N {
                        az.vec[i].coeffs[j] -= ct1.vec[i].coeffs[j];
                    }
                }

                az.invntt_tomont();
                az.reduce();
                az.freeze();

                let mut w1_prime = PolyVec::<K>::new();
                for i in 0..K {
                    for j in 0..super::super::params::N {
                        let hint = h[i * super::super::params::N + j];
                        w1_prime.vec[i].coeffs[j] = use_hint::<GAMMA2>(az.vec[i].coeffs[j], hint);
                    }
                }

                let mut w1_packed = [0u8; K * <$params>::POLYW1_PACKEDBYTES];
                for i in 0..K {
                    pack_w1::<GAMMA2>(
                        &mut w1_packed[i * <$params>::POLYW1_PACKEDBYTES
                            ..(i + 1) * <$params>::POLYW1_PACKEDBYTES],
                        &w1_prime.vec[i],
                    );
                }

                let mut c_input = [0u8; 64 + K * <$params>::POLYW1_PACKEDBYTES];
                c_input[..64].copy_from_slice(&mu);
                c_input[64..].copy_from_slice(&w1_packed);
                let c_hash = shake256_64(&c_input);

                if &c_hash[..32] != c_tilde {
                    return Err(Error::SignatureVerificationFailed);
                }

                Ok(())
            }

            fn pack_poly_eta<const ETA: usize>(r: &mut [u8], a: &Poly) {
                if ETA == 2 {
                    for i in 0..super::super::params::N / 8 {
                        r[3 * i] = ((ETA as i32 - a.coeffs[8 * i])
                            | ((ETA as i32 - a.coeffs[8 * i + 1]) << 3)
                            | ((ETA as i32 - a.coeffs[8 * i + 2]) << 6))
                            as u8;
                        r[3 * i + 1] = (((ETA as i32 - a.coeffs[8 * i + 2]) >> 2)
                            | ((ETA as i32 - a.coeffs[8 * i + 3]) << 1)
                            | ((ETA as i32 - a.coeffs[8 * i + 4]) << 4)
                            | ((ETA as i32 - a.coeffs[8 * i + 5]) << 7))
                            as u8;
                        r[3 * i + 2] = (((ETA as i32 - a.coeffs[8 * i + 5]) >> 1)
                            | ((ETA as i32 - a.coeffs[8 * i + 6]) << 2)
                            | ((ETA as i32 - a.coeffs[8 * i + 7]) << 5))
                            as u8;
                    }
                } else {
                    for i in 0..super::super::params::N / 2 {
                        r[i] = ((ETA as i32 - a.coeffs[2 * i])
                            | ((ETA as i32 - a.coeffs[2 * i + 1]) << 4))
                            as u8;
                    }
                }
            }

            fn unpack_poly_eta<const ETA: usize>(r: &mut Poly, a: &[u8]) {
                if ETA == 2 {
                    for i in 0..super::super::params::N / 8 {
                        r.coeffs[8 * i] = (a[3 * i] & 0x07) as i32;
                        r.coeffs[8 * i + 1] = ((a[3 * i] >> 3) & 0x07) as i32;
                        r.coeffs[8 * i + 2] =
                            (((a[3 * i] >> 6) | (a[3 * i + 1] << 2)) & 0x07) as i32;
                        r.coeffs[8 * i + 3] = ((a[3 * i + 1] >> 1) & 0x07) as i32;
                        r.coeffs[8 * i + 4] = ((a[3 * i + 1] >> 4) & 0x07) as i32;
                        r.coeffs[8 * i + 5] =
                            (((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 0x07) as i32;
                        r.coeffs[8 * i + 6] = ((a[3 * i + 2] >> 2) & 0x07) as i32;
                        r.coeffs[8 * i + 7] = ((a[3 * i + 2] >> 5) & 0x07) as i32;

                        for j in 0..8 {
                            r.coeffs[8 * i + j] = ETA as i32 - r.coeffs[8 * i + j];
                        }
                    }
                } else {
                    for i in 0..super::super::params::N / 2 {
                        r.coeffs[2 * i] = (a[i] & 0x0F) as i32;
                        r.coeffs[2 * i + 1] = (a[i] >> 4) as i32;
                        r.coeffs[2 * i] = ETA as i32 - r.coeffs[2 * i];
                        r.coeffs[2 * i + 1] = ETA as i32 - r.coeffs[2 * i + 1];
                    }
                }
            }

            fn pack_z<const GAMMA1: usize>(r: &mut [u8], a: &Poly) {
                if GAMMA1 == (1 << 17) {
                    for i in 0..super::super::params::N / 4 {
                        let t0 = GAMMA1 as i32 - a.coeffs[4 * i];
                        let t1 = GAMMA1 as i32 - a.coeffs[4 * i + 1];
                        let t2 = GAMMA1 as i32 - a.coeffs[4 * i + 2];
                        let t3 = GAMMA1 as i32 - a.coeffs[4 * i + 3];

                        r[9 * i] = t0 as u8;
                        r[9 * i + 1] = (t0 >> 8) as u8;
                        r[9 * i + 2] = ((t0 >> 16) | (t1 << 2)) as u8;
                        r[9 * i + 3] = (t1 >> 6) as u8;
                        r[9 * i + 4] = ((t1 >> 14) | (t2 << 4)) as u8;
                        r[9 * i + 5] = (t2 >> 4) as u8;
                        r[9 * i + 6] = ((t2 >> 12) | (t3 << 6)) as u8;
                        r[9 * i + 7] = (t3 >> 2) as u8;
                        r[9 * i + 8] = (t3 >> 10) as u8;
                    }
                } else {
                    for i in 0..super::super::params::N / 2 {
                        let t0 = GAMMA1 as i32 - a.coeffs[2 * i];
                        let t1 = GAMMA1 as i32 - a.coeffs[2 * i + 1];

                        r[5 * i] = t0 as u8;
                        r[5 * i + 1] = (t0 >> 8) as u8;
                        r[5 * i + 2] = ((t0 >> 16) | (t1 << 4)) as u8;
                        r[5 * i + 3] = (t1 >> 4) as u8;
                        r[5 * i + 4] = (t1 >> 12) as u8;
                    }
                }
            }

            fn unpack_z<const GAMMA1: usize>(r: &mut Poly, a: &[u8]) -> Result<(), Error> {
                if GAMMA1 == (1 << 17) {
                    for i in 0..super::super::params::N / 4 {
                        r.coeffs[4 * i] = a[9 * i] as i32;
                        r.coeffs[4 * i] |= (a[9 * i + 1] as i32) << 8;
                        r.coeffs[4 * i] |= ((a[9 * i + 2] as i32) & 0x03) << 16;

                        r.coeffs[4 * i + 1] = (a[9 * i + 2] as i32) >> 2;
                        r.coeffs[4 * i + 1] |= (a[9 * i + 3] as i32) << 6;
                        r.coeffs[4 * i + 1] |= ((a[9 * i + 4] as i32) & 0x0F) << 14;

                        r.coeffs[4 * i + 2] = (a[9 * i + 4] as i32) >> 4;
                        r.coeffs[4 * i + 2] |= (a[9 * i + 5] as i32) << 4;
                        r.coeffs[4 * i + 2] |= ((a[9 * i + 6] as i32) & 0x3F) << 12;

                        r.coeffs[4 * i + 3] = (a[9 * i + 6] as i32) >> 6;
                        r.coeffs[4 * i + 3] |= (a[9 * i + 7] as i32) << 2;
                        r.coeffs[4 * i + 3] |= (a[9 * i + 8] as i32) << 10;

                        for j in 0..4 {
                            r.coeffs[4 * i + j] = GAMMA1 as i32 - r.coeffs[4 * i + j];
                            if r.coeffs[4 * i + j].abs() >= GAMMA1 as i32 {
                                return Err(Error::SignatureVerificationFailed);
                            }
                        }
                    }
                } else {
                    for i in 0..super::super::params::N / 2 {
                        r.coeffs[2 * i] = a[5 * i] as i32;
                        r.coeffs[2 * i] |= (a[5 * i + 1] as i32) << 8;
                        r.coeffs[2 * i] |= ((a[5 * i + 2] as i32) & 0x0F) << 16;

                        r.coeffs[2 * i + 1] = (a[5 * i + 2] as i32) >> 4;
                        r.coeffs[2 * i + 1] |= (a[5 * i + 3] as i32) << 4;
                        r.coeffs[2 * i + 1] |= (a[5 * i + 4] as i32) << 12;

                        r.coeffs[2 * i] = GAMMA1 as i32 - r.coeffs[2 * i];
                        r.coeffs[2 * i + 1] = GAMMA1 as i32 - r.coeffs[2 * i + 1];

                        if r.coeffs[2 * i].abs() >= GAMMA1 as i32
                            || r.coeffs[2 * i + 1].abs() >= GAMMA1 as i32
                        {
                            return Err(Error::SignatureVerificationFailed);
                        }
                    }
                }
                Ok(())
            }

            fn pack_w1<const GAMMA2: usize>(r: &mut [u8], a: &Poly) {
                if GAMMA2 == ((super::super::params::Q as usize - 1) / 88) {
                    for i in 0..super::super::params::N / 4 {
                        r[3 * i] = a.coeffs[4 * i] as u8;
                        r[3 * i] |= (a.coeffs[4 * i + 1] << 6) as u8;
                        r[3 * i + 1] = (a.coeffs[4 * i + 1] >> 2) as u8;
                        r[3 * i + 1] |= (a.coeffs[4 * i + 2] << 4) as u8;
                        r[3 * i + 2] = (a.coeffs[4 * i + 2] >> 4) as u8;
                        r[3 * i + 2] |= (a.coeffs[4 * i + 3] << 2) as u8;
                    }
                } else {
                    for i in 0..super::super::params::N / 2 {
                        r[i] = (a.coeffs[2 * i] | (a.coeffs[2 * i + 1] << 4)) as u8;
                    }
                }
            }

            fn pack_hint(r: &mut [u8], h: &[bool], k: usize) {
                r[..<$params>::OMEGA + k].fill(0);

                let mut index = 0;
                for i in 0..k {
                    for j in 0..super::super::params::N {
                        if h[i * super::super::params::N + j] {
                            r[index] = j as u8;
                            index += 1;
                        }
                    }
                    r[<$params>::OMEGA + i] = index as u8;
                }
            }

            fn unpack_hint(h: &mut [bool], a: &[u8], k: usize) -> Result<(), Error> {
                h.fill(false);

                let mut index = 0;
                for i in 0..k {
                    let limit = a[<$params>::OMEGA + i] as usize;
                    if limit < index || limit > <$params>::OMEGA {
                        return Err(Error::SignatureVerificationFailed);
                    }

                    for j in index..limit {
                        if j > index && a[j] <= a[j - 1] {
                            return Err(Error::SignatureVerificationFailed);
                        }
                        h[i * super::super::params::N + a[j] as usize] = true;
                    }
                    index = limit;
                }

                for i in index..<$params>::OMEGA {
                    if a[i] != 0 {
                        return Err(Error::SignatureVerificationFailed);
                    }
                }

                Ok(())
            }
        }
    };
}

#[cfg(feature = "mldsa44")]
impl_dsa!(mldsa44, crate::ml_dsa::params::ML_DSA_44);

#[cfg(feature = "mldsa65")]
impl_dsa!(mldsa65, crate::ml_dsa::params::ML_DSA_65);

#[cfg(feature = "mldsa87")]
impl_dsa!(mldsa87, crate::ml_dsa::params::ML_DSA_87);

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "mldsa44")]
    fn test_mldsa44_sign_verify() {
        use super::mldsa44::*;
        use rand::rngs::OsRng;

        let (pk, sk) = generate(&mut OsRng);
        let msg = b"Hello, ML-DSA!";
        let ctx = b"test context";

        let sig = sign(&sk, msg, ctx, &mut OsRng).unwrap();
        verify(&pk, msg, ctx, &sig).unwrap();
    }

    #[test]
    #[cfg(feature = "mldsa65")]
    fn test_mldsa65_sign_verify() {
        use super::mldsa65::*;
        use rand::rngs::OsRng;

        let (pk, sk) = generate(&mut OsRng);
        let msg = b"Hello, ML-DSA!";
        let ctx = b"";

        let sig = sign(&sk, msg, ctx, &mut OsRng).unwrap();
        verify(&pk, msg, ctx, &sig).unwrap();
    }

    #[test]
    #[cfg(feature = "mldsa87")]
    fn test_mldsa87_sign_verify() {
        use super::mldsa87::*;
        use rand::rngs::OsRng;

        let (pk, sk) = generate(&mut OsRng);
        let msg = b"Post-quantum signatures!";
        let ctx = b"";

        let sig = sign(&sk, msg, ctx, &mut OsRng).unwrap();
        verify(&pk, msg, ctx, &sig).unwrap();
    }
}
