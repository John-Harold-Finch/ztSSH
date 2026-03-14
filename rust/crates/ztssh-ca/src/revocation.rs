//! Revocation list — 3-level revocation for ZTSSH.
//!
//! Maintained by the Root CA and distributed to Sub-CAs via snapshots.
//! Snapshots can be signed for authenticated distribution.

use std::collections::HashSet;

use ed25519_dalek::{Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use ztssh_crypto::KeyPair;

/// A revocation list with 3 levels:
/// 1. **Banned principals** — no server can issue certs for these users
/// 2. **Revoked server serials** — server licences invalidated by Root CA
/// 3. **Revoked client serials** — individual client badges invalidated
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevocationList {
    banned_principals: HashSet<String>,
    revoked_server_serials: HashSet<u64>,
    revoked_client_serials: HashSet<u64>,
}

impl RevocationList {
    /// Create an empty revocation list.
    pub fn new() -> Self {
        Self::default()
    }

    // ─── Principal bans (global) ───

    /// Ban a principal globally. No server may issue certificates for this user.
    pub fn ban_principal(&mut self, principal: impl Into<String>) {
        self.banned_principals.insert(principal.into());
    }

    /// Check if a principal is globally banned.
    pub fn is_principal_banned(&self, principal: &str) -> bool {
        self.banned_principals.contains(principal)
    }

    // ─── Server revocation ───

    /// Revoke a server's intermediate certificate.
    pub fn revoke_server(&mut self, serial: u64) {
        self.revoked_server_serials.insert(serial);
    }

    /// Check if a server serial has been revoked.
    pub fn is_server_revoked(&self, serial: u64) -> bool {
        self.revoked_server_serials.contains(&serial)
    }

    // ─── Client revocation ───

    /// Revoke a specific client certificate.
    pub fn revoke_client(&mut self, serial: u64) {
        self.revoked_client_serials.insert(serial);
    }

    /// Check if a client serial has been revoked.
    pub fn is_client_revoked(&self, serial: u64) -> bool {
        self.revoked_client_serials.contains(&serial)
    }

    // ─── Distribution ───

    /// Create an independent snapshot for distribution to Sub-CAs.
    ///
    /// Modifications to the original list after snapshot will NOT
    /// affect the snapshot — they are fully independent.
    pub fn snapshot(&self) -> Self {
        self.clone()
    }

    /// Merge another revocation list into this one (union).
    /// Used by Sub-CAs to absorb Root CA updates.
    pub fn merge(&mut self, other: &RevocationList) {
        self.banned_principals
            .extend(other.banned_principals.iter().cloned());
        self.revoked_server_serials
            .extend(&other.revoked_server_serials);
        self.revoked_client_serials
            .extend(&other.revoked_client_serials);
    }

    /// Serialize this CRL to a canonical binary form (for signing).
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("CRL serialization must not fail")
    }

    /// Deserialize from binary.
    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    /// Create a signed snapshot for authenticated distribution.
    pub fn sign(&self, signing_key: &KeyPair) -> SignedRevocationList {
        let payload = self.to_bytes();
        let signature = signing_key.sign(&payload);
        SignedRevocationList {
            payload,
            signature: signature.to_bytes().to_vec(),
            signer_public_key: signing_key.public_key_bytes(),
        }
    }
}

/// A signed revocation list for secure distribution.
///
/// Contains the serialized CRL, its Ed25519 signature, and the signer's public key.
/// Receivers verify the signature before applying updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRevocationList {
    /// Serialized `RevocationList` bytes.
    pub payload: Vec<u8>,
    /// Ed25519 signature over `payload`.
    pub signature: Vec<u8>,
    /// Public key of the signer (Root CA).
    pub signer_public_key: [u8; 32],
}

impl SignedRevocationList {
    /// Verify the signature and extract the revocation list.
    ///
    /// `expected_signer` is the public key we trust (Root CA).
    /// Returns `None` if the signature is invalid or signer doesn't match.
    pub fn verify_and_extract(&self, expected_signer: &[u8; 32]) -> Option<RevocationList> {
        if self.signer_public_key != *expected_signer {
            return None;
        }

        let sig_bytes: [u8; 64] = match self.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return None,
        };

        let verifying_key = VerifyingKey::from_bytes(&self.signer_public_key).ok()?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key.verify(&self.payload, &signature).ok()?;

        RevocationList::from_bytes(&self.payload).ok()
    }

    /// Serialize the entire signed CRL for wire transport.
    pub fn to_wire(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SignedCRL serialization must not fail")
    }

    /// Deserialize from wire format.
    pub fn from_wire(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_is_independent() {
        let mut crl = RevocationList::new();
        crl.revoke_client(1);
        let snap = crl.snapshot();

        crl.revoke_client(2);

        assert!(snap.is_client_revoked(1));
        assert!(!snap.is_client_revoked(2));
    }

    #[test]
    fn ban_principal() {
        let mut crl = RevocationList::new();
        crl.ban_principal("hacker");
        assert!(crl.is_principal_banned("hacker"));
        assert!(!crl.is_principal_banned("admin"));
    }

    #[test]
    fn revoke_server() {
        let mut crl = RevocationList::new();
        crl.revoke_server(42);
        assert!(crl.is_server_revoked(42));
        assert!(!crl.is_server_revoked(43));
    }

    #[test]
    fn merge_combines_lists() {
        let mut crl_a = RevocationList::new();
        crl_a.ban_principal("user_a");
        crl_a.revoke_client(1);

        let mut crl_b = RevocationList::new();
        crl_b.ban_principal("user_b");
        crl_b.revoke_client(2);

        crl_a.merge(&crl_b);

        assert!(crl_a.is_principal_banned("user_a"));
        assert!(crl_a.is_principal_banned("user_b"));
        assert!(crl_a.is_client_revoked(1));
        assert!(crl_a.is_client_revoked(2));
    }

    #[test]
    fn signed_crl_roundtrip() {
        let key = KeyPair::new();
        let mut crl = RevocationList::new();
        crl.ban_principal("baduser");
        crl.revoke_client(42);

        let signed = crl.sign(&key);
        let extracted = signed.verify_and_extract(&key.public_key_bytes()).unwrap();

        assert!(extracted.is_principal_banned("baduser"));
        assert!(extracted.is_client_revoked(42));
    }

    #[test]
    fn signed_crl_wrong_signer_rejected() {
        let key = KeyPair::new();
        let wrong_key = KeyPair::new();

        let crl = RevocationList::new();
        let signed = crl.sign(&key);

        // Verify with wrong key should fail
        assert!(signed
            .verify_and_extract(&wrong_key.public_key_bytes())
            .is_none());
    }

    #[test]
    fn signed_crl_tampered_payload_rejected() {
        let key = KeyPair::new();
        let mut crl = RevocationList::new();
        crl.revoke_server(99);

        let mut signed = crl.sign(&key);
        // Tamper with payload
        if !signed.payload.is_empty() {
            signed.payload[0] ^= 0xFF;
        }

        assert!(signed.verify_and_extract(&key.public_key_bytes()).is_none());
    }

    #[test]
    fn signed_crl_wire_roundtrip() {
        let key = KeyPair::new();
        let mut crl = RevocationList::new();
        crl.ban_principal("evil");
        crl.revoke_client(7);

        let signed = crl.sign(&key);
        let wire = signed.to_wire();
        let restored = super::SignedRevocationList::from_wire(&wire).unwrap();

        let extracted = restored
            .verify_and_extract(&key.public_key_bytes())
            .unwrap();
        assert!(extracted.is_principal_banned("evil"));
        assert!(extracted.is_client_revoked(7));
    }
}
