//! Short-lived client certificate (badge) — 5 minute TTL.
//!
//! Issued by a Sub-CA to a client. Contains the client's ephemeral public key,
//! the issuing Sub-CA's public key, and an Ed25519 signature from the Sub-CA.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::CryptoError;
use crate::keypair::KeyPair;

/// Magic header for client certificate wire format.
const CERT_MAGIC: &[u8; 14] = b"ZTSSH-CERT-V1\0";

/// A short-lived ZTSSH client certificate.
///
/// This is the "badge" in the hotel analogy — valid for 5 minutes,
/// must be renewed continuously during the session.
#[derive(Debug, Clone)]
pub struct ZtsshCertificate {
    /// Monotonically increasing serial number (unique per Sub-CA).
    pub serial: u64,
    /// The authenticated principal (username).
    pub principal: String,
    /// Client's ephemeral Ed25519 public key (32 bytes).
    pub subject_public_key: [u8; 32],
    /// Issuing Sub-CA's public key (32 bytes).
    pub issuer_public_key: [u8; 32],
    /// Unix timestamp when the certificate was issued.
    pub issued_at: f64,
    /// Unix timestamp when the certificate expires.
    pub expires_at: f64,
    /// Ed25519 signature from the Sub-CA over the certificate body.
    pub signature: [u8; 64],
}

impl ZtsshCertificate {
    /// Check if this certificate has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_secs_f64();
        now >= self.expires_at
    }

    /// Remaining time-to-live in seconds. Returns 0.0 if expired.
    pub fn ttl_remaining(&self) -> f64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_secs_f64();
        (self.expires_at - now).max(0.0)
    }

    /// Serialize the signable body (everything except the signature).
    /// This is what gets signed by the Sub-CA.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&self.serial.to_be_bytes());
        buf.extend_from_slice(&(self.principal.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.principal.as_bytes());
        buf.extend_from_slice(&self.subject_public_key);
        buf.extend_from_slice(&self.issuer_public_key);
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        buf
    }

    /// Verify the certificate's signature using the issuer's public key.
    pub fn verify_signature(&self) -> Result<bool, CryptoError> {
        KeyPair::verify_with_key(
            &self.issuer_public_key,
            &self.signature,
            &self.signable_bytes(),
        )
    }

    /// Serialize to wire format for transmission.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(CERT_MAGIC);
        buf.extend_from_slice(&self.serial.to_be_bytes());
        buf.extend_from_slice(&(self.principal.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.principal.as_bytes());
        buf.extend_from_slice(&self.subject_public_key);
        buf.extend_from_slice(&self.issuer_public_key);
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Deserialize from wire format.
    pub fn from_wire(data: &[u8]) -> Result<Self, CryptoError> {
        let min_len = 14 + 8 + 4 + 32 + 32 + 8 + 8 + 64; // 170 + principal
        if data.len() < min_len {
            return Err(CryptoError::InvalidWireFormat(format!(
                "too short: {} bytes, need at least {}",
                data.len(),
                min_len
            )));
        }

        let magic = &data[0..14];
        if magic != CERT_MAGIC {
            return Err(CryptoError::MagicMismatch {
                expected: String::from_utf8_lossy(CERT_MAGIC).to_string(),
                got: String::from_utf8_lossy(magic).to_string(),
            });
        }

        let mut pos = 14;

        let serial = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        let principal_len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        if data.len() < pos + principal_len + 32 + 32 + 8 + 8 + 64 {
            return Err(CryptoError::InvalidWireFormat(
                "truncated after principal length".into(),
            ));
        }

        let principal = String::from_utf8(data[pos..pos + principal_len].to_vec())
            .map_err(|e| CryptoError::InvalidWireFormat(format!("invalid UTF-8 principal: {e}")))?;
        pos += principal_len;

        let mut subject_public_key = [0u8; 32];
        subject_public_key.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let mut issuer_public_key = [0u8; 32];
        issuer_public_key.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let issued_at = f64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        let expires_at = f64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[pos..pos + 64]);

        Ok(Self {
            serial,
            principal,
            subject_public_key,
            issuer_public_key,
            issued_at,
            expires_at,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dummy_cert() -> ZtsshCertificate {
        let kp_client = KeyPair::new();
        let kp_issuer = KeyPair::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut cert = ZtsshCertificate {
            serial: 42,
            principal: "alice".into(),
            subject_public_key: kp_client.public_key_bytes(),
            issuer_public_key: kp_issuer.public_key_bytes(),
            issued_at: now,
            expires_at: now + 300.0,
            signature: [0u8; 64],
        };

        let sig = kp_issuer.sign(&cert.signable_bytes());
        cert.signature = sig.to_bytes();
        cert
    }

    #[test]
    fn wire_roundtrip() {
        let cert = make_dummy_cert();
        let wire = cert.to_wire();
        let restored = ZtsshCertificate::from_wire(&wire).unwrap();

        assert_eq!(restored.serial, 42);
        assert_eq!(restored.principal, "alice");
        assert_eq!(restored.subject_public_key, cert.subject_public_key);
        assert_eq!(restored.issuer_public_key, cert.issuer_public_key);
        assert_eq!(restored.signature, cert.signature);
    }

    #[test]
    fn signature_verification() {
        let cert = make_dummy_cert();
        assert!(cert.verify_signature().unwrap());
    }

    #[test]
    fn not_expired() {
        let cert = make_dummy_cert();
        assert!(!cert.is_expired());
        assert!(cert.ttl_remaining() > 299.0);
    }

    #[test]
    fn expired_cert() {
        let kp = KeyPair::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let cert = ZtsshCertificate {
            serial: 1,
            principal: "expired_user".into(),
            subject_public_key: kp.public_key_bytes(),
            issuer_public_key: kp.public_key_bytes(),
            issued_at: now - 600.0,
            expires_at: now - 1.0,
            signature: [0u8; 64],
        };
        assert!(cert.is_expired());
        assert_eq!(cert.ttl_remaining(), 0.0);
    }

    #[test]
    fn invalid_magic_rejected() {
        let mut wire = make_dummy_cert().to_wire();
        wire[0] = b'X';
        assert!(ZtsshCertificate::from_wire(&wire).is_err());
    }

    #[test]
    fn truncated_data_rejected() {
        assert!(ZtsshCertificate::from_wire(&[0u8; 10]).is_err());
    }
}
