//! ZTSSH error types for the crypto crate.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Ed25519 signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Certificate has expired.
    #[error("certificate expired")]
    CertificateExpired,

    /// Wire format is corrupted or truncated.
    #[error("invalid wire format: {0}")]
    InvalidWireFormat(String),

    /// Magic header mismatch during deserialization.
    #[error("magic header mismatch: expected {expected}, got {got}")]
    MagicMismatch { expected: String, got: String },

    /// Ed25519 key deserialization error.
    #[error("invalid key bytes: {0}")]
    InvalidKey(String),
}
