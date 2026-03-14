//! Protocol error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid message type: 0x{0:02X}")]
    InvalidMessageType(u8),

    #[error("message too short: {0} bytes")]
    MessageTooShort(usize),

    #[error("invalid terminate reason code: 0x{0:04X}")]
    InvalidTerminateReason(u32),

    #[error("invalid UTF-8 in message field: {0}")]
    InvalidUtf8(String),

    #[error("serialization error: {0}")]
    SerializationError(String),
}
