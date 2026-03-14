//! Protocol constants.

/// SSH private-use message type codes (RFC 4250).
pub mod msg_type {
    pub const IDENTITY_PROOF: u8 = 0xC0;
    pub const IDENTITY_CHALLENGE: u8 = 0xC1;
    pub const IDENTITY_ACK: u8 = 0xC2;
    pub const SESSION_TERMINATE: u8 = 0xC3;
    pub const EXTENSION_NEGOTIATION: u8 = 0xC4;
}

/// Reason codes for session termination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
pub enum TerminateReason {
    /// Certificate expired without renewal.
    CertExpired = 0x01,
    /// Certificate was revoked by the CA.
    CertRevoked = 0x02,
    /// Client did not respond to challenge in time.
    ChallengeTimeout = 0x03,
    /// Identity proof was invalid.
    InvalidProof = 0x04,
    /// Access policy changed.
    PolicyViolation = 0x05,
    /// Administrative revocation.
    AdminRevoke = 0x06,
    /// Principal has been globally banned.
    PrincipalBanned = 0x07,
}

impl TerminateReason {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x01 => Some(Self::CertExpired),
            0x02 => Some(Self::CertRevoked),
            0x03 => Some(Self::ChallengeTimeout),
            0x04 => Some(Self::InvalidProof),
            0x05 => Some(Self::PolicyViolation),
            0x06 => Some(Self::AdminRevoke),
            0x07 => Some(Self::PrincipalBanned),
            _ => None,
        }
    }
}

/// Default certificate TTL in seconds (5 minutes).
pub const DEFAULT_CERT_TTL: f64 = 300.0;

/// Default intermediate certificate TTL in seconds (24 hours).
pub const DEFAULT_INTERMEDIATE_TTL: f64 = 86400.0;

/// Default challenge interval in seconds.
pub const DEFAULT_CHALLENGE_INTERVAL: u32 = 60;

/// Default challenge deadline in seconds.
pub const DEFAULT_CHALLENGE_DEADLINE: u32 = 30;

/// Default renewal window — start renewing when TTL is below this (seconds).
pub const DEFAULT_RENEWAL_WINDOW: f64 = 60.0;

/// ZTSSH extension name for SSH negotiation (RFC 8308).
pub const EXTENSION_NAME: &str = "ztssh-continuous-auth@John-Harold-Finch.io";

/// Protocol version.
pub const PROTOCOL_VERSION: &str = "0.2";
