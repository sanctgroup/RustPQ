//! Error types for ML-DSA operations.

/// Errors that can occur during ML-DSA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The public key has an invalid length.
    InvalidPublicKeyLength,
    /// The secret key has an invalid length.
    InvalidSecretKeyLength,
    /// The signature has an invalid length.
    InvalidSignatureLength,
    /// The context string exceeds the maximum length of 255 bytes.
    InvalidContextLength,
    /// The signature verification failed.
    SignatureVerificationFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidPublicKeyLength => write!(f, "Invalid public key length"),
            Error::InvalidSecretKeyLength => write!(f, "Invalid secret key length"),
            Error::InvalidSignatureLength => write!(f, "Invalid signature length"),
            Error::InvalidContextLength => write!(f, "Context string too long (max 255 bytes)"),
            Error::SignatureVerificationFailed => write!(f, "Signature verification failed"),
        }
    }
}
