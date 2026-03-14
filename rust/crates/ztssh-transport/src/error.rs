//! Transport error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(#[from] ztssh_protocol::ProtocolError),

    #[error("crypto error: {0}")]
    Crypto(#[from] ztssh_crypto::CryptoError),

    #[error("CA error: {0}")]
    Ca(#[from] ztssh_ca::CaError),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("challenge timeout")]
    ChallengeTimeout,

    #[error("invalid message type: 0x{0:02X}")]
    InvalidMessageType(u8),

    #[error("message too large: {0} bytes")]
    MessageTooLarge(u32),

    #[error("policy denied: {0}")]
    PolicyDenied(String),

    #[error("rate limited: {0}")]
    RateLimited(String),
}
