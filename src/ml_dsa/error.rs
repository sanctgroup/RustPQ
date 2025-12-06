#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidPublicKeyLength,
    InvalidSecretKeyLength,
    InvalidSignatureLength,
    InvalidContextLength,
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
