//! SecP256r1MLKEM768 Hybrid KEM.
//!
//! Combines secp256r1 (P-256) ECDH with ML-KEM-768 for NIST Level 3 security.
//! Shared secret combiner: `ss = ecdh_ss || mlkem_ss`

use super::error::Error;
use crate::ml_kem::mlkem768;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use rand_core::CryptoRngCore;
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, Zeroizing};

pub const P256_PUBLIC_KEY_BYTES: usize = 65;
pub const MLKEM_PUBLIC_KEY_BYTES: usize = mlkem768::PUBLIC_KEY_BYTES;
pub const PUBLIC_KEY_BYTES: usize = P256_PUBLIC_KEY_BYTES + MLKEM_PUBLIC_KEY_BYTES;

pub const P256_SECRET_KEY_BYTES: usize = 32;
pub const MLKEM_SECRET_KEY_BYTES: usize = mlkem768::SECRET_KEY_BYTES;
pub const SECRET_KEY_BYTES: usize = P256_SECRET_KEY_BYTES + MLKEM_SECRET_KEY_BYTES;

pub const P256_CIPHERTEXT_BYTES: usize = 65;
pub const MLKEM_CIPHERTEXT_BYTES: usize = mlkem768::CIPHERTEXT_BYTES;
pub const CIPHERTEXT_BYTES: usize = P256_CIPHERTEXT_BYTES + MLKEM_CIPHERTEXT_BYTES;

pub const P256_SHARED_SECRET_BYTES: usize = 32;
pub const MLKEM_SHARED_SECRET_BYTES: usize = 32;
pub const SHARED_SECRET_BYTES: usize = P256_SHARED_SECRET_BYTES + MLKEM_SHARED_SECRET_BYTES;

#[derive(Clone)]
pub struct PublicKey {
    p256: [u8; P256_PUBLIC_KEY_BYTES],
    mlkem: mlkem768::PublicKey,
}

impl PublicKey {
    pub fn as_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        let mut bytes = [0u8; PUBLIC_KEY_BYTES];
        bytes[..P256_PUBLIC_KEY_BYTES].copy_from_slice(&self.p256);
        bytes[P256_PUBLIC_KEY_BYTES..].copy_from_slice(self.mlkem.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_BYTES {
            return Err(Error::InvalidPublicKeyLength);
        }
        let mut p256 = [0u8; P256_PUBLIC_KEY_BYTES];
        p256.copy_from_slice(&bytes[..P256_PUBLIC_KEY_BYTES]);

        let encoded = EncodedPoint::from_bytes(p256).map_err(|_| Error::InvalidEcdhPublicKey)?;
        let _ = P256PublicKey::from_encoded_point(&encoded);

        let mlkem = mlkem768::PublicKey::from_bytes(&bytes[P256_PUBLIC_KEY_BYTES..])
            .map_err(|_| Error::InvalidPublicKeyLength)?;

        Ok(Self { p256, mlkem })
    }

    pub fn p256_public_key(&self) -> &[u8; P256_PUBLIC_KEY_BYTES] {
        &self.p256
    }

    pub fn mlkem_public_key(&self) -> &mlkem768::PublicKey {
        &self.mlkem
    }
}

pub struct SecretKey {
    p256: [u8; P256_SECRET_KEY_BYTES],
    mlkem: mlkem768::SecretKey,
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.p256.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SecretKey {
    pub fn as_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_BYTES]> {
        let mut bytes = Zeroizing::new([0u8; SECRET_KEY_BYTES]);
        bytes[..P256_SECRET_KEY_BYTES].copy_from_slice(&self.p256);
        bytes[P256_SECRET_KEY_BYTES..].copy_from_slice(self.mlkem.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SECRET_KEY_BYTES {
            return Err(Error::InvalidSecretKeyLength);
        }
        let mut p256 = [0u8; P256_SECRET_KEY_BYTES];
        p256.copy_from_slice(&bytes[..P256_SECRET_KEY_BYTES]);
        let mlkem = mlkem768::SecretKey::from_bytes(&bytes[P256_SECRET_KEY_BYTES..])
            .map_err(|_| Error::InvalidSecretKeyLength)?;
        Ok(Self { p256, mlkem })
    }
}

#[derive(Clone)]
pub struct Ciphertext {
    p256: [u8; P256_CIPHERTEXT_BYTES],
    mlkem: mlkem768::Ciphertext,
}

impl Ciphertext {
    pub fn as_bytes(&self) -> [u8; CIPHERTEXT_BYTES] {
        let mut bytes = [0u8; CIPHERTEXT_BYTES];
        bytes[..P256_CIPHERTEXT_BYTES].copy_from_slice(&self.p256);
        bytes[P256_CIPHERTEXT_BYTES..].copy_from_slice(self.mlkem.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != CIPHERTEXT_BYTES {
            return Err(Error::InvalidCiphertextLength);
        }
        let mut p256 = [0u8; P256_CIPHERTEXT_BYTES];
        p256.copy_from_slice(&bytes[..P256_CIPHERTEXT_BYTES]);
        let mlkem = mlkem768::Ciphertext::from_bytes(&bytes[P256_CIPHERTEXT_BYTES..])
            .map_err(|_| Error::InvalidCiphertextLength)?;
        Ok(Self { p256, mlkem })
    }

    pub fn p256_public_key(&self) -> &[u8; P256_CIPHERTEXT_BYTES] {
        &self.p256
    }

    pub fn mlkem_ciphertext(&self) -> &mlkem768::Ciphertext {
        &self.mlkem
    }
}

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

    pub fn p256_shared_secret(&self) -> &[u8] {
        &self.bytes[..P256_SHARED_SECRET_BYTES]
    }

    pub fn mlkem_shared_secret(&self) -> &[u8] {
        &self.bytes[P256_SHARED_SECRET_BYTES..]
    }

    pub fn derive_key(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(self.bytes);
        hasher.finalize().into()
    }
}

pub fn generate(rng: &mut impl CryptoRngCore) -> (PublicKey, SecretKey) {
    let p256_sk = P256SecretKey::random(rng);
    let p256_pk = p256_sk.public_key();
    let p256_pk_bytes: [u8; P256_PUBLIC_KEY_BYTES] = p256_pk
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .expect("P-256 public key should be 65 bytes uncompressed");

    let p256_sk_bytes: [u8; P256_SECRET_KEY_BYTES] = p256_sk
        .to_bytes()
        .as_slice()
        .try_into()
        .expect("P-256 secret key should be 32 bytes");

    let (mlkem_pk, mlkem_sk) = mlkem768::generate(rng);

    let pk = PublicKey {
        p256: p256_pk_bytes,
        mlkem: mlkem_pk,
    };

    let sk = SecretKey {
        p256: p256_sk_bytes,
        mlkem: mlkem_sk,
    };

    (pk, sk)
}

pub fn encapsulate(pk: &PublicKey, rng: &mut impl CryptoRngCore) -> (Ciphertext, SharedSecret) {
    let p256_eph_sk = EphemeralSecret::random(rng);
    let p256_eph_pk = p256_eph_sk.public_key();
    let p256_eph_pk_bytes: [u8; P256_CIPHERTEXT_BYTES] = p256_eph_pk
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .expect("P-256 public key should be 65 bytes uncompressed");

    let p256_peer_pk_encoded =
        EncodedPoint::from_bytes(pk.p256).expect("stored P-256 public key should be valid");
    let p256_peer_pk = P256PublicKey::from_encoded_point(&p256_peer_pk_encoded)
        .expect("stored P-256 public key should be valid");
    let p256_ss = p256_eph_sk.diffie_hellman(&p256_peer_pk);

    let (mlkem_ct, mlkem_ss) = mlkem768::encapsulate(&pk.mlkem, rng);

    let ct = Ciphertext {
        p256: p256_eph_pk_bytes,
        mlkem: mlkem_ct,
    };

    let mut ss = SharedSecret {
        bytes: [0u8; SHARED_SECRET_BYTES],
    };
    ss.bytes[..P256_SHARED_SECRET_BYTES].copy_from_slice(p256_ss.raw_secret_bytes());
    ss.bytes[P256_SHARED_SECRET_BYTES..].copy_from_slice(mlkem_ss.as_bytes());

    (ct, ss)
}

pub fn decapsulate(sk: &SecretKey, ct: &Ciphertext) -> SharedSecret {
    let p256_sk = p256::SecretKey::from_bytes((&sk.p256).into())
        .expect("stored P-256 secret key should be valid");
    let p256_eph_pk_encoded =
        EncodedPoint::from_bytes(ct.p256).expect("ciphertext P-256 public key should be valid");
    let p256_eph_pk = P256PublicKey::from_encoded_point(&p256_eph_pk_encoded)
        .expect("ciphertext P-256 public key should be valid");

    let p256_ss = p256::ecdh::diffie_hellman(p256_sk.to_nonzero_scalar(), p256_eph_pk.as_affine());

    let mlkem_ss = mlkem768::decapsulate(&sk.mlkem, &ct.mlkem);

    let mut ss = SharedSecret {
        bytes: [0u8; SHARED_SECRET_BYTES],
    };
    ss.bytes[..P256_SHARED_SECRET_BYTES].copy_from_slice(p256_ss.raw_secret_bytes());
    ss.bytes[P256_SHARED_SECRET_BYTES..].copy_from_slice(mlkem_ss.as_bytes());

    ss
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        use rand::rngs::OsRng;

        let (pk, sk) = generate(&mut OsRng);
        let (ct, ss_sender) = encapsulate(&pk, &mut OsRng);
        let ss_receiver = decapsulate(&sk, &ct);

        assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
    }

    #[test]
    fn test_serialization() {
        use rand::rngs::OsRng;

        let (pk, sk) = generate(&mut OsRng);

        let pk_bytes = pk.as_bytes();
        let pk_restored = PublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk.as_bytes(), pk_restored.as_bytes());

        let sk_bytes = sk.as_bytes();
        let sk_restored = SecretKey::from_bytes(&*sk_bytes).unwrap();
        assert_eq!(*sk.as_bytes(), *sk_restored.as_bytes());

        let (ct, _) = encapsulate(&pk, &mut OsRng);
        let ct_bytes = ct.as_bytes();
        let ct_restored = Ciphertext::from_bytes(&ct_bytes).unwrap();
        assert_eq!(ct.as_bytes(), ct_restored.as_bytes());
    }

    #[test]
    fn test_shared_secret_size() {
        use rand::rngs::OsRng;

        let (pk, _) = generate(&mut OsRng);
        let (_, ss) = encapsulate(&pk, &mut OsRng);

        assert_eq!(ss.as_bytes().len(), 64);
    }
}
