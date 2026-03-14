//! Protocol message types with binary serialization.
//!
//! Each message carries a `msg_type` byte prefix for dispatch.

use serde::{Deserialize, Serialize};

use crate::constants::{msg_type, TerminateReason};
use crate::error::ProtocolError;

/// Server → Client: Challenge the client's identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityChallenge {
    pub sequence_number: u32,
    pub timestamp: u64,
    pub nonce: Vec<u8>,
    pub deadline_seconds: u32,
}

/// Client → Server: Prove identity with cert + signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProof {
    pub sequence_number: u32,
    pub timestamp: u64,
    pub certificate: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Server → Client: Acknowledge successful verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAck {
    pub sequence_number: u32,
    pub next_challenge_in_seconds: u32,
}

/// Server → Client: Terminate the session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTerminate {
    pub sequence_number: u32,
    pub reason_code: TerminateReason,
    pub reason_message: String,
}

// ─── Binary Serialization ───
//
// Format: [msg_type: u8] [payload...]
// Payload fields are length-prefixed for variable-length data.

impl IdentityChallenge {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.push(msg_type::IDENTITY_CHALLENGE);
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&(self.nonce.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.deadline_seconds.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 1 + 4 + 8 + 4 {
            return Err(ProtocolError::MessageTooShort(data.len()));
        }
        if data[0] != msg_type::IDENTITY_CHALLENGE {
            return Err(ProtocolError::InvalidMessageType(data[0]));
        }

        let mut pos = 1;
        let sequence_number = read_u32(data, &mut pos)?;
        let timestamp = read_u64(data, &mut pos)?;
        let nonce_len = read_u32(data, &mut pos)? as usize;

        if pos + nonce_len + 4 > data.len() {
            return Err(ProtocolError::MessageTooShort(data.len()));
        }
        let nonce = data[pos..pos + nonce_len].to_vec();
        pos += nonce_len;

        let deadline_seconds = read_u32(data, &mut pos)?;

        Ok(Self {
            sequence_number,
            timestamp,
            nonce,
            deadline_seconds,
        })
    }
}

impl IdentityProof {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.push(msg_type::IDENTITY_PROOF);
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&(self.certificate.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.certificate);
        buf.extend_from_slice(&(self.signature.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 1 + 4 + 8 + 4 {
            return Err(ProtocolError::MessageTooShort(data.len()));
        }
        if data[0] != msg_type::IDENTITY_PROOF {
            return Err(ProtocolError::InvalidMessageType(data[0]));
        }

        let mut pos = 1;
        let sequence_number = read_u32(data, &mut pos)?;
        let timestamp = read_u64(data, &mut pos)?;

        let cert_len = read_u32(data, &mut pos)? as usize;
        if pos + cert_len > data.len() {
            return Err(ProtocolError::MessageTooShort(data.len()));
        }
        let certificate = data[pos..pos + cert_len].to_vec();
        pos += cert_len;

        let sig_len = read_u32(data, &mut pos)? as usize;
        if pos + sig_len > data.len() {
            return Err(ProtocolError::MessageTooShort(data.len()));
        }
        let signature = data[pos..pos + sig_len].to_vec();

        Ok(Self {
            sequence_number,
            timestamp,
            certificate,
            signature,
        })
    }
}

impl IdentityAck {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.push(msg_type::IDENTITY_ACK);
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.next_challenge_in_seconds.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 1 + 4 + 4 {
            return Err(ProtocolError::MessageTooShort(data.len()));
        }
        if data[0] != msg_type::IDENTITY_ACK {
            return Err(ProtocolError::InvalidMessageType(data[0]));
        }

        let mut pos = 1;
        let sequence_number = read_u32(data, &mut pos)?;
        let next_challenge_in_seconds = read_u32(data, &mut pos)?;

        Ok(Self {
            sequence_number,
            next_challenge_in_seconds,
        })
    }
}

impl SessionTerminate {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.push(msg_type::SESSION_TERMINATE);
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&(self.reason_code as u32).to_be_bytes());
        buf.extend_from_slice(&(self.reason_message.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.reason_message.as_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 1 + 4 + 4 + 4 {
            return Err(ProtocolError::MessageTooShort(data.len()));
        }
        if data[0] != msg_type::SESSION_TERMINATE {
            return Err(ProtocolError::InvalidMessageType(data[0]));
        }

        let mut pos = 1;
        let sequence_number = read_u32(data, &mut pos)?;
        let reason_u32 = read_u32(data, &mut pos)?;
        let reason_code = TerminateReason::from_u32(reason_u32)
            .ok_or(ProtocolError::InvalidTerminateReason(reason_u32))?;

        let msg_len = read_u32(data, &mut pos)? as usize;
        if pos + msg_len > data.len() {
            return Err(ProtocolError::MessageTooShort(data.len()));
        }
        let reason_message = String::from_utf8(data[pos..pos + msg_len].to_vec())
            .map_err(|e| ProtocolError::InvalidUtf8(e.to_string()))?;

        Ok(Self {
            sequence_number,
            reason_code,
            reason_message,
        })
    }
}

// ─── Helpers ───

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, ProtocolError> {
    if *pos + 4 > data.len() {
        return Err(ProtocolError::MessageTooShort(data.len()));
    }
    let val = u32::from_be_bytes(data[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(val)
}

fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, ProtocolError> {
    if *pos + 8 > data.len() {
        return Err(ProtocolError::MessageTooShort(data.len()));
    }
    let val = u64::from_be_bytes(data[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ztssh_crypto::generate_nonce;

    #[test]
    fn challenge_roundtrip() {
        let nonce = generate_nonce(32);
        let msg = IdentityChallenge {
            sequence_number: 42,
            timestamp: 1700000000,
            nonce: nonce.clone(),
            deadline_seconds: 30,
        };
        let data = msg.serialize();
        let restored = IdentityChallenge::deserialize(&data).unwrap();

        assert_eq!(restored.sequence_number, 42);
        assert_eq!(restored.timestamp, 1700000000);
        assert_eq!(restored.nonce, nonce);
        assert_eq!(restored.deadline_seconds, 30);
    }

    #[test]
    fn proof_roundtrip() {
        let msg = IdentityProof {
            sequence_number: 7,
            timestamp: 1700000001,
            certificate: b"fake-cert-data".to_vec(),
            signature: b"fake-signature".to_vec(),
        };
        let data = msg.serialize();
        let restored = IdentityProof::deserialize(&data).unwrap();

        assert_eq!(restored.sequence_number, 7);
        assert_eq!(restored.certificate, b"fake-cert-data");
        assert_eq!(restored.signature, b"fake-signature");
    }

    #[test]
    fn ack_roundtrip() {
        let msg = IdentityAck {
            sequence_number: 10,
            next_challenge_in_seconds: 60,
        };
        let data = msg.serialize();
        let restored = IdentityAck::deserialize(&data).unwrap();

        assert_eq!(restored.sequence_number, 10);
        assert_eq!(restored.next_challenge_in_seconds, 60);
    }

    #[test]
    fn terminate_roundtrip() {
        let msg = SessionTerminate {
            sequence_number: 99,
            reason_code: TerminateReason::CertExpired,
            reason_message: "Certificate expired without renewal".into(),
        };
        let data = msg.serialize();
        let restored = SessionTerminate::deserialize(&data).unwrap();

        assert_eq!(restored.sequence_number, 99);
        assert_eq!(restored.reason_code, TerminateReason::CertExpired);
        assert_eq!(
            restored.reason_message,
            "Certificate expired without renewal"
        );
    }

    #[test]
    fn invalid_msg_type_rejected() {
        let data = vec![0xFF, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(IdentityChallenge::deserialize(&data).is_err());
    }

    #[test]
    fn truncated_message_rejected() {
        assert!(IdentityChallenge::deserialize(&[0xC1]).is_err());
    }

    #[test]
    fn all_terminate_reasons_valid() {
        for code in 0x01..=0x07u32 {
            assert!(TerminateReason::from_u32(code).is_some());
        }
        assert!(TerminateReason::from_u32(0x00).is_none());
        assert!(TerminateReason::from_u32(0xFF).is_none());
    }
}
