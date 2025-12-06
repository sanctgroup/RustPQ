use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidPublicKeyLength,
    InvalidSecretKeyLength,
    InvalidCiphertextLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidPublicKeyLength => write!(f, "invalid public key length"),
            Error::InvalidSecretKeyLength => write!(f, "invalid secret key length"),
            Error::InvalidCiphertextLength => write!(f, "invalid ciphertext length"),
        }
    }
}
