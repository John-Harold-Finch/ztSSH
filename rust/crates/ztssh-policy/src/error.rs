//! Policy error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy denied: {0}")]
    Denied(String),

    #[error("rate limited: {0}")]
    RateLimited(String),

    #[error("invalid policy configuration: {0}")]
    InvalidConfig(String),

    #[error("failed to load policy file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    ParseError(#[from] toml::de::Error),
}
