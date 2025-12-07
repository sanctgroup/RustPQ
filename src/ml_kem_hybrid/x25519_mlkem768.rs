//! X25519MLKEM768 Hybrid KEM.
//!
//! Combines X25519 ECDH with ML-KEM-768 for NIST Level 3 security.
//! Shared secret combiner: `ss = mlkem_ss || x25519_ss`

use super::error::Error;
use crate::ml_kem::mlkem768;
use rand_core::CryptoRngCore;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

pub const X25519_PUBLIC_KEY_BYTES: usize = 32;
pub const MLKEM_PUBLIC_KEY_BYTES: usize = mlkem768::PUBLIC_KEY_BYTES;
pub const PUBLIC_KEY_BYTES: usize = MLKEM_PUBLIC_KEY_BYTES + X25519_PUBLIC_KEY_BYTES;

pub const X25519_SECRET_KEY_BYTES: usize = 32;
pub const MLKEM_SECRET_KEY_BYTES: usize = mlkem768::SECRET_KEY_BYTES;
pub const SECRET_KEY_BYTES: usize = MLKEM_SECRET_KEY_BYTES + X25519_SECRET_KEY_BYTES;

pub const X25519_CIPHERTEXT_BYTES: usize = 32;
pub const MLKEM_CIPHERTEXT_BYTES: usize = mlkem768::CIPHERTEXT_BYTES;
pub const CIPHERTEXT_BYTES: usize = MLKEM_CIPHERTEXT_BYTES + X25519_CIPHERTEXT_BYTES;

pub const X25519_SHARED_SECRET_BYTES: usize = 32;
pub const MLKEM_SHARED_SECRET_BYTES: usize = 32;
pub const SHARED_SECRET_BYTES: usize = MLKEM_SHARED_SECRET_BYTES + X25519_SHARED_SECRET_BYTES;

#[derive(Clone)]
pub struct PublicKey {
    mlkem: mlkem768::PublicKey,
    x25519: [u8; X25519_PUBLIC_KEY_BYTES],
}

impl PublicKey {
    pub fn as_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        let mut bytes = [0u8; PUBLIC_KEY_BYTES];
        bytes[..MLKEM_PUBLIC_KEY_BYTES].copy_from_slice(self.mlkem.as_bytes());
        bytes[MLKEM_PUBLIC_KEY_BYTES..].copy_from_slice(&self.x25519);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_BYTES {
            return Err(Error::InvalidPublicKeyLength);
        }
        let mlkem = mlkem768::PublicKey::from_bytes(&bytes[..MLKEM_PUBLIC_KEY_BYTES])
            .map_err(|_| Error::InvalidPublicKeyLength)?;
        let mut x25519 = [0u8; X25519_PUBLIC_KEY_BYTES];
        x25519.copy_from_slice(&bytes[MLKEM_PUBLIC_KEY_BYTES..]);
        Ok(Self { mlkem, x25519 })
    }

    pub fn mlkem_public_key(&self) -> &mlkem768::PublicKey {
        &self.mlkem
    }

    pub fn x25519_public_key(&self) -> &[u8; X25519_PUBLIC_KEY_BYTES] {
        &self.x25519
    }
}

pub struct SecretKey {
    mlkem: mlkem768::SecretKey,
    x25519: [u8; X25519_SECRET_KEY_BYTES],
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.x25519.zeroize();
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
        bytes[..MLKEM_SECRET_KEY_BYTES].copy_from_slice(self.mlkem.as_bytes());
        bytes[MLKEM_SECRET_KEY_BYTES..].copy_from_slice(&self.x25519);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SECRET_KEY_BYTES {
            return Err(Error::InvalidSecretKeyLength);
        }
        let mlkem = mlkem768::SecretKey::from_bytes(&bytes[..MLKEM_SECRET_KEY_BYTES])
            .map_err(|_| Error::InvalidSecretKeyLength)?;
        let mut x25519 = [0u8; X25519_SECRET_KEY_BYTES];
        x25519.copy_from_slice(&bytes[MLKEM_SECRET_KEY_BYTES..]);
        Ok(Self { mlkem, x25519 })
    }
}

#[derive(Clone)]
pub struct Ciphertext {
    mlkem: mlkem768::Ciphertext,
    x25519: [u8; X25519_CIPHERTEXT_BYTES],
}

impl Ciphertext {
    pub fn as_bytes(&self) -> [u8; CIPHERTEXT_BYTES] {
        let mut bytes = [0u8; CIPHERTEXT_BYTES];
        bytes[..MLKEM_CIPHERTEXT_BYTES].copy_from_slice(self.mlkem.as_bytes());
        bytes[MLKEM_CIPHERTEXT_BYTES..].copy_from_slice(&self.x25519);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != CIPHERTEXT_BYTES {
            return Err(Error::InvalidCiphertextLength);
        }
        let mlkem = mlkem768::Ciphertext::from_bytes(&bytes[..MLKEM_CIPHERTEXT_BYTES])
            .map_err(|_| Error::InvalidCiphertextLength)?;
        let mut x25519 = [0u8; X25519_CIPHERTEXT_BYTES];
        x25519.copy_from_slice(&bytes[MLKEM_CIPHERTEXT_BYTES..]);
        Ok(Self { mlkem, x25519 })
    }

    pub fn mlkem_ciphertext(&self) -> &mlkem768::Ciphertext {
        &self.mlkem
    }

    pub fn x25519_public_key(&self) -> &[u8; X25519_CIPHERTEXT_BYTES] {
        &self.x25519
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

    pub fn mlkem_shared_secret(&self) -> &[u8] {
        &self.bytes[..MLKEM_SHARED_SECRET_BYTES]
    }

    pub fn x25519_shared_secret(&self) -> &[u8] {
        &self.bytes[MLKEM_SHARED_SECRET_BYTES..]
    }

    pub fn derive_key(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.bytes);
        hasher.finalize().into()
    }
}

pub fn generate(rng: &mut impl CryptoRngCore) -> (PublicKey, SecretKey) {
    let (mlkem_pk, mlkem_sk) = mlkem768::generate(rng);

    let x25519_sk = StaticSecret::random_from_rng(rng);
    let x25519_pk = X25519PublicKey::from(&x25519_sk);

    let pk = PublicKey {
        mlkem: mlkem_pk,
        x25519: x25519_pk.to_bytes(),
    };

    let sk = SecretKey {
        mlkem: mlkem_sk,
        x25519: x25519_sk.to_bytes(),
    };

    (pk, sk)
}

pub fn encapsulate(pk: &PublicKey, rng: &mut impl CryptoRngCore) -> (Ciphertext, SharedSecret) {
    let (mlkem_ct, mlkem_ss) = mlkem768::encapsulate(&pk.mlkem, rng);

    let x25519_eph_sk = EphemeralSecret::random_from_rng(rng);
    let x25519_eph_pk = X25519PublicKey::from(&x25519_eph_sk);
    let x25519_peer_pk = X25519PublicKey::from(pk.x25519);
    let x25519_ss = x25519_eph_sk.diffie_hellman(&x25519_peer_pk);

    let ct = Ciphertext {
        mlkem: mlkem_ct,
        x25519: x25519_eph_pk.to_bytes(),
    };

    let mut ss = SharedSecret {
        bytes: [0u8; SHARED_SECRET_BYTES],
    };
    ss.bytes[..MLKEM_SHARED_SECRET_BYTES].copy_from_slice(mlkem_ss.as_bytes());
    ss.bytes[MLKEM_SHARED_SECRET_BYTES..].copy_from_slice(x25519_ss.as_bytes());

    (ct, ss)
}

pub fn decapsulate(sk: &SecretKey, ct: &Ciphertext) -> SharedSecret {
    let mlkem_ss = mlkem768::decapsulate(&sk.mlkem, &ct.mlkem);

    let x25519_sk = StaticSecret::from(sk.x25519);
    let x25519_eph_pk = X25519PublicKey::from(ct.x25519);
    let x25519_ss = x25519_sk.diffie_hellman(&x25519_eph_pk);

    let mut ss = SharedSecret {
        bytes: [0u8; SHARED_SECRET_BYTES],
    };
    ss.bytes[..MLKEM_SHARED_SECRET_BYTES].copy_from_slice(mlkem_ss.as_bytes());
    ss.bytes[MLKEM_SHARED_SECRET_BYTES..].copy_from_slice(x25519_ss.as_bytes());

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

        assert_eq!(ss.as_bytes().len(), 64);
    }
}
