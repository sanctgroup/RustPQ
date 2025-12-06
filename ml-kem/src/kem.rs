use crate::indcpa;
use crate::params::{self, POLYBYTES, SYMBYTES};
use crate::symmetric::{hash_g, hash_h, kdf};
use rand_core::CryptoRngCore;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

macro_rules! impl_kem {
    ($mod_name:ident, $K:expr, $ETA1:expr, $ETA2:expr, $DU:expr, $DV:expr,
     $PK_BYTES:expr, $SK_BYTES:expr, $CT_BYTES:expr) => {
        pub mod $mod_name {
            use super::*;

            pub const PUBLIC_KEY_BYTES: usize = $PK_BYTES;
            pub const SECRET_KEY_BYTES: usize = $SK_BYTES;
            pub const CIPHERTEXT_BYTES: usize = $CT_BYTES;
            pub const SHARED_SECRET_BYTES: usize = 32;

            #[derive(Clone)]
            pub struct PublicKey {
                bytes: [u8; PUBLIC_KEY_BYTES],
            }

            impl PublicKey {
                pub fn as_bytes(&self) -> &[u8] {
                    &self.bytes
                }

                pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
                    if bytes.len() != PUBLIC_KEY_BYTES {
                        return Err(crate::Error::InvalidPublicKeyLength);
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

                pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
                    if bytes.len() != SECRET_KEY_BYTES {
                        return Err(crate::Error::InvalidSecretKeyLength);
                    }
                    let mut sk = Self {
                        bytes: [0u8; SECRET_KEY_BYTES],
                    };
                    sk.bytes.copy_from_slice(bytes);
                    Ok(sk)
                }
            }

            #[derive(Clone)]
            pub struct Ciphertext {
                bytes: [u8; CIPHERTEXT_BYTES],
            }

            impl Ciphertext {
                pub fn as_bytes(&self) -> &[u8] {
                    &self.bytes
                }

                pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
                    if bytes.len() != CIPHERTEXT_BYTES {
                        return Err(crate::Error::InvalidCiphertextLength);
                    }
                    let mut ct = Self {
                        bytes: [0u8; CIPHERTEXT_BYTES],
                    };
                    ct.bytes.copy_from_slice(bytes);
                    Ok(ct)
                }
            }

            #[derive(Clone)]
            pub struct SharedSecret {
                bytes: [u8; SHARED_SECRET_BYTES],
            }

            impl Zeroize for SharedSecret {
                fn zeroize(&mut self) {
                    self.bytes.zeroize();
                }
            }

            impl Drop for SharedSecret {
                fn drop(&mut self) {
                    self.zeroize();
                }
            }

            impl SharedSecret {
                pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] {
                    &self.bytes
                }
            }

            pub fn generate(rng: &mut impl CryptoRngCore) -> (PublicKey, SecretKey) {
                let mut d = [0u8; SYMBYTES];
                let mut z = [0u8; SYMBYTES];
                rng.fill_bytes(&mut d);
                rng.fill_bytes(&mut z);
                generate_deterministic(&d, &z)
            }

            pub fn generate_deterministic(d: &[u8; 32], z: &[u8; 32]) -> (PublicKey, SecretKey) {
                let mut pk = PublicKey {
                    bytes: [0u8; PUBLIC_KEY_BYTES],
                };
                let mut sk = SecretKey {
                    bytes: [0u8; SECRET_KEY_BYTES],
                };

                let indcpa_sk_len = $K * POLYBYTES;

                indcpa::keypair::<$K, $ETA1>(&mut pk.bytes, &mut sk.bytes[..indcpa_sk_len], d);

                sk.bytes[indcpa_sk_len..indcpa_sk_len + PUBLIC_KEY_BYTES]
                    .copy_from_slice(&pk.bytes);

                let h = hash_h(&pk.bytes);
                sk.bytes
                    [indcpa_sk_len + PUBLIC_KEY_BYTES..indcpa_sk_len + PUBLIC_KEY_BYTES + SYMBYTES]
                    .copy_from_slice(&h);

                sk.bytes[indcpa_sk_len + PUBLIC_KEY_BYTES + SYMBYTES..].copy_from_slice(z);

                (pk, sk)
            }

            pub fn encapsulate(
                pk: &PublicKey,
                rng: &mut impl CryptoRngCore,
            ) -> (Ciphertext, SharedSecret) {
                let mut m = [0u8; SYMBYTES];
                rng.fill_bytes(&mut m);
                encapsulate_deterministic(pk, &m)
            }

            pub fn encapsulate_deterministic(
                pk: &PublicKey,
                m: &[u8; 32],
            ) -> (Ciphertext, SharedSecret) {
                let mut ct = Ciphertext {
                    bytes: [0u8; CIPHERTEXT_BYTES],
                };

                let h = hash_h(&pk.bytes);

                let mut buf = [0u8; 64];
                buf[..SYMBYTES].copy_from_slice(m);
                buf[SYMBYTES..SYMBYTES * 2].copy_from_slice(&h);
                let kr = hash_g(&buf);

                indcpa::enc::<$K, $ETA1, $ETA2, $DU, $DV>(
                    &mut ct.bytes,
                    m,
                    &pk.bytes,
                    kr[SYMBYTES..].try_into().unwrap(),
                );

                let mut ss = SharedSecret {
                    bytes: [0u8; SHARED_SECRET_BYTES],
                };
                ss.bytes.copy_from_slice(&kr[..SYMBYTES]);

                (ct, ss)
            }

            pub fn decapsulate(sk: &SecretKey, ct: &Ciphertext) -> SharedSecret {
                let indcpa_sk_len = $K * POLYBYTES;
                let pk_start = indcpa_sk_len;
                let pk_end = pk_start + PUBLIC_KEY_BYTES;
                let h_start = pk_end;
                let h_end = h_start + SYMBYTES;
                let z_start = h_end;

                let indcpa_sk = &sk.bytes[..indcpa_sk_len];
                let pk = &sk.bytes[pk_start..pk_end];
                let h = &sk.bytes[h_start..h_end];
                let z = &sk.bytes[z_start..z_start + SYMBYTES];

                let mut m_prime = Zeroizing::new([0u8; SYMBYTES]);
                indcpa::dec::<$K, $DU, $DV>(&mut m_prime, &ct.bytes, indcpa_sk);

                let mut buf = [0u8; 64];
                buf[..SYMBYTES].copy_from_slice(&*m_prime);
                buf[SYMBYTES..SYMBYTES * 2].copy_from_slice(h);
                let kr = hash_g(&buf);

                let mut ct_cmp = [0u8; CIPHERTEXT_BYTES];
                indcpa::enc::<$K, $ETA1, $ETA2, $DU, $DV>(
                    &mut ct_cmp,
                    &m_prime,
                    pk,
                    kr[SYMBYTES..].try_into().unwrap(),
                );

                let eq = ct.bytes.ct_eq(&ct_cmp);

                let mut kdf_input = [0u8; SYMBYTES + CIPHERTEXT_BYTES];
                kdf_input[..SYMBYTES].copy_from_slice(z);
                kdf_input[SYMBYTES..].copy_from_slice(&ct.bytes);
                let k_fail = kdf(&kdf_input);

                let mut ss = SharedSecret {
                    bytes: [0u8; SHARED_SECRET_BYTES],
                };
                for i in 0..SHARED_SECRET_BYTES {
                    ss.bytes[i] = u8::conditional_select(&k_fail[i], &kr[i], eq);
                }

                ss
            }
        }
    };
}

#[cfg(feature = "mlkem512")]
impl_kem!(
    mlkem512,
    { params::mlkem512::K },
    { params::mlkem512::ETA1 },
    { params::mlkem512::ETA2 },
    { params::mlkem512::DU },
    { params::mlkem512::DV },
    params::mlkem512::PUBLICKEYBYTES,
    params::mlkem512::SECRETKEYBYTES,
    params::mlkem512::CIPHERTEXTBYTES
);

#[cfg(feature = "mlkem768")]
impl_kem!(
    mlkem768,
    { params::mlkem768::K },
    { params::mlkem768::ETA1 },
    { params::mlkem768::ETA2 },
    { params::mlkem768::DU },
    { params::mlkem768::DV },
    params::mlkem768::PUBLICKEYBYTES,
    params::mlkem768::SECRETKEYBYTES,
    params::mlkem768::CIPHERTEXTBYTES
);

#[cfg(feature = "mlkem1024")]
impl_kem!(
    mlkem1024,
    { params::mlkem1024::K },
    { params::mlkem1024::ETA1 },
    { params::mlkem1024::ETA2 },
    { params::mlkem1024::DU },
    { params::mlkem1024::DV },
    params::mlkem1024::PUBLICKEYBYTES,
    params::mlkem1024::SECRETKEYBYTES,
    params::mlkem1024::CIPHERTEXTBYTES
);

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "mlkem768")]
    fn test_mlkem768_roundtrip() {
        use super::mlkem768::*;
        use rand::rngs::OsRng;

        let (pk, sk) = generate(&mut OsRng);
        let (ct, ss_sender) = encapsulate(&pk, &mut OsRng);
        let ss_receiver = decapsulate(&sk, &ct);

        assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
    }

    #[test]
    #[cfg(feature = "mlkem512")]
    fn test_mlkem512_roundtrip() {
        use super::mlkem512::*;
        use rand::rngs::OsRng;

        let (pk, sk) = generate(&mut OsRng);
        let (ct, ss_sender) = encapsulate(&pk, &mut OsRng);
        let ss_receiver = decapsulate(&sk, &ct);

        assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
    }

    #[test]
    #[cfg(feature = "mlkem1024")]
    fn test_mlkem1024_roundtrip() {
        use super::mlkem1024::*;
        use rand::rngs::OsRng;

        let (pk, sk) = generate(&mut OsRng);
        let (ct, ss_sender) = encapsulate(&pk, &mut OsRng);
        let ss_receiver = decapsulate(&sk, &ct);

        assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
    }

    #[test]
    #[cfg(feature = "mlkem768")]
    fn test_implicit_rejection() {
        use super::mlkem768::*;
        use rand::rngs::OsRng;

        let (pk, sk) = generate(&mut OsRng);
        let (ct, ss_sender) = encapsulate(&pk, &mut OsRng);

        let mut bad_bytes = [0u8; CIPHERTEXT_BYTES];
        bad_bytes.copy_from_slice(ct.as_bytes());
        bad_bytes[0] ^= 0xFF;
        let bad_ct = Ciphertext::from_bytes(&bad_bytes).unwrap();

        let ss_bad = decapsulate(&sk, &bad_ct);
        assert_ne!(ss_sender.as_bytes(), ss_bad.as_bytes());
    }

    #[test]
    #[cfg(feature = "mlkem768")]
    fn test_deterministic_keygen() {
        use super::mlkem768::*;

        let d = [0u8; 32];
        let z = [1u8; 32];

        let (pk1, sk1) = generate_deterministic(&d, &z);
        let (pk2, sk2) = generate_deterministic(&d, &z);

        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
        assert_eq!(sk1.as_bytes(), sk2.as_bytes());
    }

    #[test]
    #[cfg(feature = "mlkem768")]
    fn test_deterministic_encaps() {
        use super::mlkem768::*;

        let d = [0u8; 32];
        let z = [1u8; 32];
        let m = [2u8; 32];

        let (pk, _) = generate_deterministic(&d, &z);
        let (ct1, ss1) = encapsulate_deterministic(&pk, &m);
        let (ct2, ss2) = encapsulate_deterministic(&pk, &m);

        assert_eq!(ct1.as_bytes(), ct2.as_bytes());
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    #[cfg(feature = "mlkem768")]
    fn test_encrypt_decrypt_hello_world() {
        use super::mlkem768::*;
        use rand::rngs::OsRng;

        let message = b"Hello World";

        let (pk, sk) = generate(&mut OsRng);
        let (ct, ss_sender) = encapsulate(&pk, &mut OsRng);
        let ss_receiver = decapsulate(&sk, &ct);

        assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());

        let key = ss_sender.as_bytes();
        let mut ciphertext = [0u8; 11];
        for i in 0..message.len() {
            ciphertext[i] = message[i] ^ key[i];
        }

        let key = ss_receiver.as_bytes();
        let mut plaintext = [0u8; 11];
        for i in 0..ciphertext.len() {
            plaintext[i] = ciphertext[i] ^ key[i];
        }

        assert_eq!(&plaintext, message);
        assert_eq!(core::str::from_utf8(&plaintext).unwrap(), "Hello World");
    }
}
