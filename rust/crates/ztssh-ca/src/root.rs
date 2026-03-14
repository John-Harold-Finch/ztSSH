//! Root Certificate Authority — offline, issues server licences.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ztssh_crypto::{IntermediateCertificate, KeyPair};
use ztssh_protocol::DEFAULT_INTERMEDIATE_TTL;

use crate::revocation::RevocationList;
use crate::verify::CertVerifyResult;

/// The Root CA — meant to run offline (air-gapped).
///
/// Responsibilities:
/// - Issue `IntermediateCertificate` to authorize servers
/// - Maintain the global `RevocationList`
/// - Revoke servers and ban principals
pub struct RootCa {
    key_pair: KeyPair,
    serial_counter: AtomicU64,
    /// The global revocation list maintained by this Root CA.
    pub revocation_list: RevocationList,
    /// TTL for intermediate certificates in seconds (default: 24h).
    pub intermediate_ttl: f64,
}

impl RootCa {
    /// Create a new Root CA with a fresh keypair.
    pub fn new() -> Self {
        Self {
            key_pair: KeyPair::new(),
            serial_counter: AtomicU64::new(1),
            revocation_list: RevocationList::new(),
            intermediate_ttl: DEFAULT_INTERMEDIATE_TTL,
        }
    }

    /// Restore a Root CA from a persisted keypair.
    pub fn from_keypair(key_pair: KeyPair) -> Self {
        Self {
            key_pair,
            serial_counter: AtomicU64::new(1),
            revocation_list: RevocationList::new(),
            intermediate_ttl: DEFAULT_INTERMEDIATE_TTL,
        }
    }

    /// Get the private key bytes for persistence.
    pub fn key_bytes(&self) -> [u8; 32] {
        self.key_pair.to_bytes()
    }

    /// Set the serial counter (for restoring state).
    pub fn set_serial_counter(&self, value: u64) {
        self.serial_counter.store(value, Ordering::SeqCst);
    }

    /// Get the current serial counter value.
    pub fn next_serial(&self) -> u64 {
        self.serial_counter.load(Ordering::SeqCst)
    }

    /// Get the Root CA's public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key_pair.public_key_bytes()
    }

    /// Authorize a server by issuing an IntermediateCertificate.
    ///
    /// # Arguments
    /// * `server_public_key` — The Sub-CA's Ed25519 public key
    /// * `server_id` — Human-readable server identifier
    /// * `allowed_principals` — Which users the server may certify (`None` = wildcard)
    pub fn authorize_server(
        &self,
        server_public_key: [u8; 32],
        server_id: impl Into<String>,
        allowed_principals: Option<Vec<String>>,
    ) -> IntermediateCertificate {
        let serial = self.serial_counter.fetch_add(1, Ordering::SeqCst);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let principals = allowed_principals.unwrap_or_else(|| vec!["*".into()]);

        let mut cert = IntermediateCertificate {
            serial,
            server_id: server_id.into(),
            subject_public_key: server_public_key,
            issuer_public_key: self.key_pair.public_key_bytes(),
            allowed_principals: principals,
            issued_at: now,
            expires_at: now + self.intermediate_ttl,
            signature: [0u8; 64],
        };

        let sig = self.key_pair.sign(&cert.signable_bytes());
        cert.signature = sig.to_bytes();
        cert
    }

    /// Verify an intermediate certificate.
    /// Uses constant-time comparison for public key checks.
    pub fn verify_intermediate(&self, cert: &IntermediateCertificate) -> CertVerifyResult {
        // Check issuer (constant-time to prevent timing leaks)
        if !KeyPair::ct_eq_keys(&cert.issuer_public_key, &self.key_pair.public_key_bytes()) {
            return CertVerifyResult::fail("issuer_mismatch");
        }

        // Check revocation
        if self.revocation_list.is_server_revoked(cert.serial) {
            return CertVerifyResult::fail("server_revoked");
        }

        // Check expiration
        if cert.is_expired() {
            return CertVerifyResult::fail("expired");
        }

        // Check signature
        match cert.verify_signature() {
            Ok(true) => CertVerifyResult::ok(&cert.server_id, cert.ttl_remaining()),
            Ok(false) => CertVerifyResult::fail("invalid_signature"),
            Err(_) => CertVerifyResult::fail("signature_error"),
        }
    }

    /// Revoke a server's intermediate certificate.
    pub fn revoke_server(&mut self, serial: u64) {
        self.revocation_list.revoke_server(serial);
    }

    /// Globally ban a principal — no server may issue certs for this user.
    pub fn ban_principal(&mut self, principal: impl Into<String>) {
        self.revocation_list.ban_principal(principal);
    }

    /// Revoke a specific client certificate globally.
    pub fn revoke_client(&mut self, serial: u64) {
        self.revocation_list.revoke_client(serial);
    }
}

impl Default for RootCa {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_server_basic() {
        let root = RootCa::new();
        let server_kp = KeyPair::new();
        let cert = root.authorize_server(server_kp.public_key_bytes(), "srv-01", None);

        assert_eq!(cert.server_id, "srv-01");
        assert_eq!(cert.issuer_public_key, root.public_key_bytes());
        assert_eq!(cert.allowed_principals, vec!["*"]);
        assert!(!cert.is_expired());
    }

    #[test]
    fn verify_intermediate_valid() {
        let root = RootCa::new();
        let server_kp = KeyPair::new();
        let cert = root.authorize_server(server_kp.public_key_bytes(), "srv-02", None);

        let result = root.verify_intermediate(&cert);
        assert!(result.valid);
        assert_eq!(result.reason, "ok");
    }

    #[test]
    fn verify_wrong_root() {
        let root1 = RootCa::new();
        let root2 = RootCa::new();
        let server_kp = KeyPair::new();
        let cert = root1.authorize_server(server_kp.public_key_bytes(), "srv-03", None);

        let result = root2.verify_intermediate(&cert);
        assert!(!result.valid);
        assert_eq!(result.reason, "issuer_mismatch");
    }

    #[test]
    fn revoke_server_works() {
        let mut root = RootCa::new();
        let server_kp = KeyPair::new();
        let cert = root.authorize_server(server_kp.public_key_bytes(), "srv-04", None);

        root.revoke_server(cert.serial);
        let result = root.verify_intermediate(&cert);
        assert!(!result.valid);
        assert_eq!(result.reason, "server_revoked");
    }

    #[test]
    fn ban_principal_works() {
        let mut root = RootCa::new();
        root.ban_principal("hacker");
        assert!(root.revocation_list.is_principal_banned("hacker"));
        assert!(!root.revocation_list.is_principal_banned("admin"));
    }

    #[test]
    fn serial_increments() {
        let root = RootCa::new();
        let kp = KeyPair::new();
        let c1 = root.authorize_server(kp.public_key_bytes(), "a", None);
        let c2 = root.authorize_server(kp.public_key_bytes(), "b", None);
        assert!(c2.serial > c1.serial);
    }

    #[test]
    fn restricted_principals() {
        let root = RootCa::new();
        let kp = KeyPair::new();
        let cert = root.authorize_server(
            kp.public_key_bytes(),
            "restricted",
            Some(vec!["alice".into(), "bob".into()]),
        );
        assert!(cert.can_certify("alice"));
        assert!(cert.can_certify("bob"));
        assert!(!cert.can_certify("charlie"));
    }
}
