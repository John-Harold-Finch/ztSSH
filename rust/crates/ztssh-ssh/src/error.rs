//! SSH transport error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshTransportError {
    #[error("SSH error: {0}")]
    Ssh(#[from] russh::Error),

    #[error("transport error: {0}")]
    Transport(#[from] ztssh_transport::TransportError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("channel closed")]
    ChannelClosed,

    #[error("authentication failed")]
    AuthFailed,

    #[error("{0}")]
    Other(String),
}
