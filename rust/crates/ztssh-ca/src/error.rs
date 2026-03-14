//! CA error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaError {
    /// Sub-CA has no valid intermediate certificate.
    #[error("no valid intermediate certificate — server not authorized by Root CA")]
    NotAuthorized,

    /// Principal is not in the server's allowed list.
    #[error("principal '{0}' not authorized for this server")]
    PrincipalNotAuthorized(String),

    /// Principal has been globally banned by Root CA.
    #[error("principal '{0}' is globally banned")]
    PrincipalBanned(String),

    /// The intermediate certificate has expired.
    #[error("intermediate certificate expired")]
    IntermediateExpired,

    /// Cryptographic error from the underlying layer.
    #[error("crypto error: {0}")]
    CryptoError(#[from] ztssh_crypto::CryptoError),
}
