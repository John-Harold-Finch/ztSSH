//! Intermediate certificate — server licence from Root CA (24h TTL).
//!
//! Authorizes a server's Sub-CA to issue client certificates.
//! Contains allowed principals (or wildcard "*").

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::CryptoError;
use crate::keypair::KeyPair;

/// Magic header for intermediate certificate wire format.
const INTERMEDIATE_MAGIC: &[u8; 21] = b"ZTSSH-INTERMEDIATE-V1";

/// An intermediate certificate issued by the Root CA to a server.
///
/// This is the "franchise licence" in the hotel analogy — it authorizes
/// the server's embedded Sub-CA to issue client badges.
#[derive(Debug, Clone)]
pub struct IntermediateCertificate {
    /// Monotonically increasing serial number (unique per Root CA).
    pub serial: u64,
    /// Human-readable server identifier.
    pub server_id: String,
    /// Server Sub-CA's Ed25519 public key (32 bytes).
    pub subject_public_key: [u8; 32],
    /// Root CA's Ed25519 public key (32 bytes).
    pub issuer_public_key: [u8; 32],
    /// Principals this server is allowed to certify. `["*"]` = unrestricted.
    pub allowed_principals: Vec<String>,
    /// Unix timestamp when the certificate was issued.
    pub issued_at: f64,
    /// Unix timestamp when the certificate expires.
    pub expires_at: f64,
    /// Ed25519 signature from the Root CA.
    pub signature: [u8; 64],
}

impl IntermediateCertificate {
    /// Check if this server licence has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_secs_f64();
        now >= self.expires_at
    }

    /// Remaining time-to-live in seconds.
    pub fn ttl_remaining(&self) -> f64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_secs_f64();
        (self.expires_at - now).max(0.0)
    }

    /// Check if this server is allowed to certify a given principal.
    pub fn can_certify(&self, principal: &str) -> bool {
        self.allowed_principals.iter().any(|p| p == "*" || p == principal)
    }

    /// Serialize the signable body (everything except signature).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&self.serial.to_be_bytes());
        buf.extend_from_slice(&(self.server_id.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.server_id.as_bytes());
        buf.extend_from_slice(&self.subject_public_key);
        buf.extend_from_slice(&self.issuer_public_key);
        buf.extend_from_slice(&(self.allowed_principals.len() as u32).to_be_bytes());
        for p in &self.allowed_principals {
            buf.extend_from_slice(&(p.len() as u32).to_be_bytes());
            buf.extend_from_slice(p.as_bytes());
        }
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        buf
    }

    /// Verify the certificate's signature against the issuer's public key.
    pub fn verify_signature(&self) -> Result<bool, CryptoError> {
        KeyPair::verify_with_key(
            &self.issuer_public_key,
            &self.signature,
            &self.signable_bytes(),
        )
    }

    /// Serialize to wire format.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(INTERMEDIATE_MAGIC);
        buf.extend_from_slice(&self.serial.to_be_bytes());
        buf.extend_from_slice(&(self.server_id.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.server_id.as_bytes());
        buf.extend_from_slice(&self.subject_public_key);
        buf.extend_from_slice(&self.issuer_public_key);
        buf.extend_from_slice(&(self.allowed_principals.len() as u32).to_be_bytes());
        for p in &self.allowed_principals {
            buf.extend_from_slice(&(p.len() as u32).to_be_bytes());
            buf.extend_from_slice(p.as_bytes());
        }
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Deserialize from wire format.
    pub fn from_wire(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 21 {
            return Err(CryptoError::InvalidWireFormat("too short for magic".into()));
        }

        let magic = &data[0..21];
        if magic != INTERMEDIATE_MAGIC {
            return Err(CryptoError::MagicMismatch {
                expected: String::from_utf8_lossy(INTERMEDIATE_MAGIC).to_string(),
                got: String::from_utf8_lossy(magic).to_string(),
            });
        }

        let mut pos = 21;

        let serial = read_u64(data, &mut pos)?;
        let server_id = read_string(data, &mut pos)?;

        let subject_public_key = read_bytes_32(data, &mut pos)?;
        let issuer_public_key = read_bytes_32(data, &mut pos)?;

        let num_principals = read_u32(data, &mut pos)? as usize;
        let mut allowed_principals = Vec::with_capacity(num_principals);
        for _ in 0..num_principals {
            allowed_principals.push(read_string(data, &mut pos)?);
        }

        let issued_at = read_f64(data, &mut pos)?;
        let expires_at = read_f64(data, &mut pos)?;

        let signature = read_bytes_64(data, &mut pos)?;

        Ok(Self {
            serial,
            server_id,
            subject_public_key,
            issuer_public_key,
            allowed_principals,
            issued_at,
            expires_at,
            signature,
        })
    }
}

// ─── Wire format helpers ───

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, CryptoError> {
    if *pos + 4 > data.len() {
        return Err(CryptoError::InvalidWireFormat("truncated u32".into()));
    }
    let val = u32::from_be_bytes(data[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(val)
}

fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, CryptoError> {
    if *pos + 8 > data.len() {
        return Err(CryptoError::InvalidWireFormat("truncated u64".into()));
    }
    let val = u64::from_be_bytes(data[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(val)
}

fn read_f64(data: &[u8], pos: &mut usize) -> Result<f64, CryptoError> {
    if *pos + 8 > data.len() {
        return Err(CryptoError::InvalidWireFormat("truncated f64".into()));
    }
    let val = f64::from_be_bytes(data[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(val)
}

fn read_string(data: &[u8], pos: &mut usize) -> Result<String, CryptoError> {
    let len = read_u32(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(CryptoError::InvalidWireFormat("truncated string".into()));
    }
    let s = String::from_utf8(data[*pos..*pos + len].to_vec())
        .map_err(|e| CryptoError::InvalidWireFormat(format!("invalid UTF-8: {e}")))?;
    *pos += len;
    Ok(s)
}

fn read_bytes_32(data: &[u8], pos: &mut usize) -> Result<[u8; 32], CryptoError> {
    if *pos + 32 > data.len() {
        return Err(CryptoError::InvalidWireFormat("truncated 32-byte field".into()));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[*pos..*pos + 32]);
    *pos += 32;
    Ok(buf)
}

fn read_bytes_64(data: &[u8], pos: &mut usize) -> Result<[u8; 64], CryptoError> {
    if *pos + 64 > data.len() {
        return Err(CryptoError::InvalidWireFormat("truncated 64-byte field".into()));
    }
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&data[*pos..*pos + 64]);
    *pos += 64;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dummy_intermediate() -> (KeyPair, IntermediateCertificate) {
        let root_kp = KeyPair::new();
        let server_kp = KeyPair::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut cert = IntermediateCertificate {
            serial: 1,
            server_id: "srv-01".into(),
            subject_public_key: server_kp.public_key_bytes(),
            issuer_public_key: root_kp.public_key_bytes(),
            allowed_principals: vec!["*".into()],
            issued_at: now,
            expires_at: now + 86400.0,
            signature: [0u8; 64],
        };

        let sig = root_kp.sign(&cert.signable_bytes());
        cert.signature = sig.to_bytes();
        (root_kp, cert)
    }

    #[test]
    fn wire_roundtrip() {
        let (_, cert) = make_dummy_intermediate();
        let wire = cert.to_wire();
        let restored = IntermediateCertificate::from_wire(&wire).unwrap();

        assert_eq!(restored.serial, 1);
        assert_eq!(restored.server_id, "srv-01");
        assert_eq!(restored.allowed_principals, vec!["*"]);
        assert_eq!(restored.subject_public_key, cert.subject_public_key);
        assert_eq!(restored.signature, cert.signature);
    }

    #[test]
    fn wire_roundtrip_multiple_principals() {
        let root_kp = KeyPair::new();
        let server_kp = KeyPair::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut cert = IntermediateCertificate {
            serial: 2,
            server_id: "restricted-srv".into(),
            subject_public_key: server_kp.public_key_bytes(),
            issuer_public_key: root_kp.public_key_bytes(),
            allowed_principals: vec!["alice".into(), "bob".into(), "charlie".into()],
            issued_at: now,
            expires_at: now + 86400.0,
            signature: [0u8; 64],
        };
        let sig = root_kp.sign(&cert.signable_bytes());
        cert.signature = sig.to_bytes();

        let wire = cert.to_wire();
        let restored = IntermediateCertificate::from_wire(&wire).unwrap();
        assert_eq!(
            restored.allowed_principals,
            vec!["alice", "bob", "charlie"]
        );
    }

    #[test]
    fn signature_verification() {
        let (_, cert) = make_dummy_intermediate();
        assert!(cert.verify_signature().unwrap());
    }

    #[test]
    fn can_certify_wildcard() {
        let (_, cert) = make_dummy_intermediate();
        assert!(cert.can_certify("anyone"));
        assert!(cert.can_certify("alice"));
    }

    #[test]
    fn can_certify_restricted() {
        let root_kp = KeyPair::new();
        let cert = IntermediateCertificate {
            serial: 3,
            server_id: "srv".into(),
            subject_public_key: [0u8; 32],
            issuer_public_key: root_kp.public_key_bytes(),
            allowed_principals: vec!["alice".into(), "bob".into()],
            issued_at: 0.0,
            expires_at: f64::MAX,
            signature: [0u8; 64],
        };
        assert!(cert.can_certify("alice"));
        assert!(cert.can_certify("bob"));
        assert!(!cert.can_certify("charlie"));
    }

    #[test]
    fn not_expired() {
        let (_, cert) = make_dummy_intermediate();
        assert!(!cert.is_expired());
    }

    #[test]
    fn invalid_magic_rejected() {
        let mut wire = make_dummy_intermediate().1.to_wire();
        wire[0] = b'X';
        assert!(IntermediateCertificate::from_wire(&wire).is_err());
    }
}
