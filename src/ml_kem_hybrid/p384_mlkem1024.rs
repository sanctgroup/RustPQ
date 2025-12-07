//! SecP384r1MLKEM1024 Hybrid KEM.
//!
//! Combines secp384r1 (P-384) ECDH with ML-KEM-1024 for NIST Level 5 security.
//! Shared secret combiner: `ss = ecdh_ss || mlkem_ss`

use super::error::Error;
use crate::ml_kem::mlkem1024;
use p384::ecdh::EphemeralSecret;
use p384::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p384::{EncodedPoint, PublicKey as P384PublicKey, SecretKey as P384SecretKey};
use rand_core::CryptoRngCore;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

pub const P384_PUBLIC_KEY_BYTES: usize = 97;
pub const MLKEM_PUBLIC_KEY_BYTES: usize = mlkem1024::PUBLIC_KEY_BYTES;
pub const PUBLIC_KEY_BYTES: usize = P384_PUBLIC_KEY_BYTES + MLKEM_PUBLIC_KEY_BYTES;

pub const P384_SECRET_KEY_BYTES: usize = 48;
pub const MLKEM_SECRET_KEY_BYTES: usize = mlkem1024::SECRET_KEY_BYTES;
pub const SECRET_KEY_BYTES: usize = P384_SECRET_KEY_BYTES + MLKEM_SECRET_KEY_BYTES;

pub const P384_CIPHERTEXT_BYTES: usize = 97;
pub const MLKEM_CIPHERTEXT_BYTES: usize = mlkem1024::CIPHERTEXT_BYTES;
pub const CIPHERTEXT_BYTES: usize = P384_CIPHERTEXT_BYTES + MLKEM_CIPHERTEXT_BYTES;

pub const P384_SHARED_SECRET_BYTES: usize = 48;
pub const MLKEM_SHARED_SECRET_BYTES: usize = 32;
pub const SHARED_SECRET_BYTES: usize = P384_SHARED_SECRET_BYTES + MLKEM_SHARED_SECRET_BYTES;

#[derive(Clone)]
pub struct PublicKey {
    p384: [u8; P384_PUBLIC_KEY_BYTES],
    mlkem: mlkem1024::PublicKey,
}

impl PublicKey {
    pub fn as_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        let mut bytes = [0u8; PUBLIC_KEY_BYTES];
        bytes[..P384_PUBLIC_KEY_BYTES].copy_from_slice(&self.p384);
        bytes[P384_PUBLIC_KEY_BYTES..].copy_from_slice(self.mlkem.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_BYTES {
            return Err(Error::InvalidPublicKeyLength);
        }
        let mut p384 = [0u8; P384_PUBLIC_KEY_BYTES];
        p384.copy_from_slice(&bytes[..P384_PUBLIC_KEY_BYTES]);

        let encoded = EncodedPoint::from_bytes(p384).map_err(|_| Error::InvalidEcdhPublicKey)?;
        let _ = P384PublicKey::from_encoded_point(&encoded);

        let mlkem = mlkem1024::PublicKey::from_bytes(&bytes[P384_PUBLIC_KEY_BYTES..])
            .map_err(|_| Error::InvalidPublicKeyLength)?;

        Ok(Self { p384, mlkem })
    }

    pub fn p384_public_key(&self) -> &[u8; P384_PUBLIC_KEY_BYTES] {
        &self.p384
    }

    pub fn mlkem_public_key(&self) -> &mlkem1024::PublicKey {
        &self.mlkem
    }
}

pub struct SecretKey {
    p384: [u8; P384_SECRET_KEY_BYTES],
    mlkem: mlkem1024::SecretKey,
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.p384.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SecretKey {
    pub fn as_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        let mut bytes = [0u8; SECRET_KEY_BYTES];
        bytes[..P384_SECRET_KEY_BYTES].copy_from_slice(&self.p384);
        bytes[P384_SECRET_KEY_BYTES..].copy_from_slice(self.mlkem.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SECRET_KEY_BYTES {
            return Err(Error::InvalidSecretKeyLength);
        }
        let mut p384 = [0u8; P384_SECRET_KEY_BYTES];
        p384.copy_from_slice(&bytes[..P384_SECRET_KEY_BYTES]);
        let mlkem = mlkem1024::SecretKey::from_bytes(&bytes[P384_SECRET_KEY_BYTES..])
            .map_err(|_| Error::InvalidSecretKeyLength)?;
        Ok(Self { p384, mlkem })
    }
}

#[derive(Clone)]
pub struct Ciphertext {
    p384: [u8; P384_CIPHERTEXT_BYTES],
    mlkem: mlkem1024::Ciphertext,
}

impl Ciphertext {
    pub fn as_bytes(&self) -> [u8; CIPHERTEXT_BYTES] {
        let mut bytes = [0u8; CIPHERTEXT_BYTES];
        bytes[..P384_CIPHERTEXT_BYTES].copy_from_slice(&self.p384);
        bytes[P384_CIPHERTEXT_BYTES..].copy_from_slice(self.mlkem.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != CIPHERTEXT_BYTES {
            return Err(Error::InvalidCiphertextLength);
        }
        let mut p384 = [0u8; P384_CIPHERTEXT_BYTES];
        p384.copy_from_slice(&bytes[..P384_CIPHERTEXT_BYTES]);
        let mlkem = mlkem1024::Ciphertext::from_bytes(&bytes[P384_CIPHERTEXT_BYTES..])
            .map_err(|_| Error::InvalidCiphertextLength)?;
        Ok(Self { p384, mlkem })
    }

    pub fn p384_public_key(&self) -> &[u8; P384_CIPHERTEXT_BYTES] {
        &self.p384
    }

    pub fn mlkem_ciphertext(&self) -> &mlkem1024::Ciphertext {
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

    pub fn p384_shared_secret(&self) -> &[u8] {
        &self.bytes[..P384_SHARED_SECRET_BYTES]
    }

    pub fn mlkem_shared_secret(&self) -> &[u8] {
        &self.bytes[P384_SHARED_SECRET_BYTES..]
    }

    pub fn derive_key(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(self.bytes);
        hasher.finalize().into()
    }
}

pub fn generate(rng: &mut impl CryptoRngCore) -> (PublicKey, SecretKey) {
    let p384_sk = P384SecretKey::random(rng);
    let p384_pk = p384_sk.public_key();
    let p384_pk_bytes: [u8; P384_PUBLIC_KEY_BYTES] = p384_pk
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .expect("P-384 public key should be 97 bytes uncompressed");

    let p384_sk_bytes: [u8; P384_SECRET_KEY_BYTES] = p384_sk
        .to_bytes()
        .as_slice()
        .try_into()
        .expect("P-384 secret key should be 48 bytes");

    let (mlkem_pk, mlkem_sk) = mlkem1024::generate(rng);

    let pk = PublicKey {
        p384: p384_pk_bytes,
        mlkem: mlkem_pk,
    };

    let sk = SecretKey {
        p384: p384_sk_bytes,
        mlkem: mlkem_sk,
    };

    (pk, sk)
}

pub fn encapsulate(pk: &PublicKey, rng: &mut impl CryptoRngCore) -> (Ciphertext, SharedSecret) {
    let p384_eph_sk = EphemeralSecret::random(rng);
    let p384_eph_pk = p384_eph_sk.public_key();
    let p384_eph_pk_bytes: [u8; P384_CIPHERTEXT_BYTES] = p384_eph_pk
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .expect("P-384 public key should be 97 bytes uncompressed");

    let p384_peer_pk_encoded =
        EncodedPoint::from_bytes(pk.p384).expect("stored P-384 public key should be valid");
    let p384_peer_pk = P384PublicKey::from_encoded_point(&p384_peer_pk_encoded)
        .expect("stored P-384 public key should be valid");
    let p384_ss = p384_eph_sk.diffie_hellman(&p384_peer_pk);

    let (mlkem_ct, mlkem_ss) = mlkem1024::encapsulate(&pk.mlkem, rng);

    let ct = Ciphertext {
        p384: p384_eph_pk_bytes,
        mlkem: mlkem_ct,
    };

    let mut ss = SharedSecret {
        bytes: [0u8; SHARED_SECRET_BYTES],
    };
    ss.bytes[..P384_SHARED_SECRET_BYTES].copy_from_slice(p384_ss.raw_secret_bytes());
    ss.bytes[P384_SHARED_SECRET_BYTES..].copy_from_slice(mlkem_ss.as_bytes());

    (ct, ss)
}

pub fn decapsulate(sk: &SecretKey, ct: &Ciphertext) -> SharedSecret {
    let p384_sk = p384::SecretKey::from_bytes((&sk.p384).into())
        .expect("stored P-384 secret key should be valid");
    let p384_eph_pk_encoded =
        EncodedPoint::from_bytes(ct.p384).expect("ciphertext P-384 public key should be valid");
    let p384_eph_pk = P384PublicKey::from_encoded_point(&p384_eph_pk_encoded)
        .expect("ciphertext P-384 public key should be valid");

    let p384_ss = p384::ecdh::diffie_hellman(p384_sk.to_nonzero_scalar(), p384_eph_pk.as_affine());

    let mlkem_ss = mlkem1024::decapsulate(&sk.mlkem, &ct.mlkem);

    let mut ss = SharedSecret {
        bytes: [0u8; SHARED_SECRET_BYTES],
    };
    ss.bytes[..P384_SHARED_SECRET_BYTES].copy_from_slice(p384_ss.raw_secret_bytes());
    ss.bytes[P384_SHARED_SECRET_BYTES..].copy_from_slice(mlkem_ss.as_bytes());

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
        let sk_restored = SecretKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(sk.as_bytes(), sk_restored.as_bytes());

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

        assert_eq!(ss.as_bytes().len(), 80);
    }
}
