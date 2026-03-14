//! Keystore error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("key not found: {0}")]
    NotFound(String),

    #[error("key already exists: {0}")]
    AlreadyExists(String),

    #[error("invalid key data: {0}")]
    InvalidKeyData(String),

    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),
}
