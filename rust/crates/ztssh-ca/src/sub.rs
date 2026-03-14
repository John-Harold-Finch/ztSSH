//! Sub-CA — embedded per-server, issues client badges.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ztssh_crypto::{IntermediateCertificate, KeyPair, ZtsshCertificate};
use ztssh_protocol::DEFAULT_CERT_TTL;

use crate::error::CaError;
use crate::revocation::RevocationList;
use crate::verify::CertVerifyResult;

/// A Sub-CA embedded in each ZTSSH server.
///
/// Responsibilities:
/// - Issue short-lived client certificates (5 min) — NO network calls
/// - Verify client certificates during challenge-response
/// - Maintain a local revocation list (merged with Root CA snapshots)
pub struct SubCa {
    key_pair: KeyPair,
    serial_counter: AtomicU64,
    /// The intermediate certificate from the Root CA (server licence).
    pub intermediate_cert: Option<IntermediateCertificate>,
    /// The Root CA's public key (for chain verification).
    pub root_public_key: Option<[u8; 32]>,
    /// Local + global revocation list.
    pub revocation_list: RevocationList,
    /// TTL for client certificates in seconds (default: 300s = 5 min).
    pub cert_ttl: f64,
}

impl SubCa {
    /// Create a new Sub-CA with a fresh keypair. Not yet authorized.
    pub fn new() -> Self {
        Self {
            key_pair: KeyPair::new(),
            serial_counter: AtomicU64::new(1),
            intermediate_cert: None,
            root_public_key: None,
            revocation_list: RevocationList::new(),
            cert_ttl: DEFAULT_CERT_TTL,
        }
    }

    /// Restore a Sub-CA from a persisted keypair.
    pub fn from_keypair(key_pair: KeyPair) -> Self {
        Self {
            key_pair,
            serial_counter: AtomicU64::new(1),
            intermediate_cert: None,
            root_public_key: None,
            revocation_list: RevocationList::new(),
            cert_ttl: DEFAULT_CERT_TTL,
        }
    }

    /// Get the private key bytes for persistence.
    pub fn key_bytes(&self) -> [u8; 32] {
        self.key_pair.to_bytes()
    }

    /// Get the Sub-CA's public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key_pair.public_key_bytes()
    }

    /// Check if this Sub-CA has been authorized by a Root CA.
    pub fn is_authorized(&self) -> bool {
        self.intermediate_cert.is_some()
    }

    /// Issue a short-lived client certificate.
    ///
    /// This operation is **purely local** — no network calls.
    ///
    /// # Errors
    /// - `CaError::NotAuthorized` if no intermediate cert
    /// - `CaError::PrincipalNotAuthorized` if server can't certify this user
    /// - `CaError::PrincipalBanned` if user is globally banned
    pub fn issue_certificate(
        &self,
        subject_public_key: [u8; 32],
        principal: impl Into<String>,
    ) -> Result<ZtsshCertificate, CaError> {
        let principal = principal.into();

        // Check authorization
        let intermediate = self
            .intermediate_cert
            .as_ref()
            .ok_or(CaError::NotAuthorized)?;

        // Check principal authorization
        if !intermediate.can_certify(&principal) {
            return Err(CaError::PrincipalNotAuthorized(principal));
        }

        // Check global ban
        if self.revocation_list.is_principal_banned(&principal) {
            return Err(CaError::PrincipalBanned(principal));
        }

        // Check intermediate cert not expired
        if intermediate.is_expired() {
            return Err(CaError::IntermediateExpired);
        }

        let serial = self.serial_counter.fetch_add(1, Ordering::SeqCst);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut cert = ZtsshCertificate {
            serial,
            principal,
            subject_public_key,
            issuer_public_key: self.key_pair.public_key_bytes(),
            issued_at: now,
            expires_at: now + self.cert_ttl,
            signature: [0u8; 64],
        };

        let sig = self.key_pair.sign(&cert.signable_bytes());
        cert.signature = sig.to_bytes();

        Ok(cert)
    }

    /// Verify a client certificate.
    ///
    /// Checks: issuer, revocation, expiration, signature — all local.
    /// Uses constant-time comparison for public key checks.
    pub fn verify_certificate(&self, cert: &ZtsshCertificate) -> CertVerifyResult {
        // Check issuer matches this Sub-CA (constant-time to prevent timing leaks)
        if !KeyPair::ct_eq_keys(&cert.issuer_public_key, &self.key_pair.public_key_bytes()) {
            return CertVerifyResult::fail("issuer_mismatch");
        }

        // Check revocation
        if self.revocation_list.is_client_revoked(cert.serial) {
            return CertVerifyResult::fail("revoked");
        }

        // Check principal ban
        if self.revocation_list.is_principal_banned(&cert.principal) {
            return CertVerifyResult::fail("principal_banned");
        }

        // Check expiration
        if cert.is_expired() {
            return CertVerifyResult::fail("expired");
        }

        // Check signature
        match cert.verify_signature() {
            Ok(true) => CertVerifyResult::ok(&cert.principal, cert.ttl_remaining()),
            Ok(false) => CertVerifyResult::fail("invalid_signature"),
            Err(_) => CertVerifyResult::fail("signature_error"),
        }
    }

    /// Revoke a client certificate locally.
    pub fn revoke_client(&mut self, serial: u64) {
        self.revocation_list.revoke_client(serial);
    }

    /// Update the revocation list with a snapshot from the Root CA.
    pub fn update_revocation_list(&mut self, snapshot: RevocationList) {
        self.revocation_list.merge(&snapshot);
    }
}

impl Default for SubCa {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::RootCa;

    /// Helper: create an authorized Sub-CA.
    fn make_authorized_sub_ca() -> (RootCa, SubCa) {
        let root = RootCa::new();
        let mut sub_ca = SubCa::new();
        let cert = root.authorize_server(sub_ca.public_key_bytes(), "test-server", None);
        sub_ca.intermediate_cert = Some(cert);
        sub_ca.root_public_key = Some(root.public_key_bytes());
        (root, sub_ca)
    }

    #[test]
    fn issue_certificate() {
        let (_, sub_ca) = make_authorized_sub_ca();
        let client_kp = KeyPair::new();
        let cert = sub_ca
            .issue_certificate(client_kp.public_key_bytes(), "alice")
            .unwrap();

        assert_eq!(cert.principal, "alice");
        assert_eq!(cert.issuer_public_key, sub_ca.public_key_bytes());
        assert!(!cert.is_expired());
        assert!(cert.ttl_remaining() > 299.0);
    }

    #[test]
    fn verify_valid_certificate() {
        let (_, sub_ca) = make_authorized_sub_ca();
        let kp = KeyPair::new();
        let cert = sub_ca
            .issue_certificate(kp.public_key_bytes(), "bob")
            .unwrap();

        let result = sub_ca.verify_certificate(&cert);
        assert!(result.valid);
        assert_eq!(result.reason, "ok");
        assert_eq!(result.principal.as_deref(), Some("bob"));
    }

    #[test]
    fn cannot_issue_without_authorization() {
        let sub_ca = SubCa::new();
        let kp = KeyPair::new();
        let err = sub_ca
            .issue_certificate(kp.public_key_bytes(), "alice")
            .unwrap_err();
        assert!(matches!(err, CaError::NotAuthorized));
    }

    #[test]
    fn cannot_certify_unauthorized_principal() {
        let root = RootCa::new();
        let mut sub_ca = SubCa::new();
        let cert = root.authorize_server(
            sub_ca.public_key_bytes(),
            "restricted",
            Some(vec!["alice".into()]),
        );
        sub_ca.intermediate_cert = Some(cert);

        let kp = KeyPair::new();
        // Alice is fine
        assert!(sub_ca
            .issue_certificate(kp.public_key_bytes(), "alice")
            .is_ok());
        // Bob is not authorized
        let err = sub_ca
            .issue_certificate(kp.public_key_bytes(), "bob")
            .unwrap_err();
        assert!(matches!(err, CaError::PrincipalNotAuthorized(_)));
    }

    #[test]
    fn banned_principal() {
        let (mut root, mut sub_ca) = make_authorized_sub_ca();
        root.ban_principal("hacker");
        sub_ca.update_revocation_list(root.revocation_list.snapshot());

        let kp = KeyPair::new();
        let err = sub_ca
            .issue_certificate(kp.public_key_bytes(), "hacker")
            .unwrap_err();
        assert!(matches!(err, CaError::PrincipalBanned(_)));
    }

    #[test]
    fn revoke_client_locally() {
        let (_, mut sub_ca) = make_authorized_sub_ca();
        let kp = KeyPair::new();
        let cert = sub_ca
            .issue_certificate(kp.public_key_bytes(), "charlie")
            .unwrap();

        sub_ca.revoke_client(cert.serial);
        let result = sub_ca.verify_certificate(&cert);
        assert!(!result.valid);
        assert_eq!(result.reason, "revoked");
    }

    #[test]
    fn global_revocation_propagates() {
        let (mut root, mut sub_ca) = make_authorized_sub_ca();
        let kp = KeyPair::new();
        let cert = sub_ca
            .issue_certificate(kp.public_key_bytes(), "dave")
            .unwrap();

        root.revoke_client(cert.serial);
        sub_ca.update_revocation_list(root.revocation_list.snapshot());

        let result = sub_ca.verify_certificate(&cert);
        assert!(!result.valid);
        assert_eq!(result.reason, "revoked");
    }

    #[test]
    fn verify_expired_certificate() {
        let (_, mut sub_ca) = make_authorized_sub_ca();
        sub_ca.cert_ttl = 0.0; // Expire immediately
        let kp = KeyPair::new();
        let cert = sub_ca
            .issue_certificate(kp.public_key_bytes(), "dave")
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));
        let result = sub_ca.verify_certificate(&cert);
        assert!(!result.valid);
        assert_eq!(result.reason, "expired");
    }

    #[test]
    fn verify_wrong_sub_ca() {
        let root = RootCa::new();
        let mut sub_ca1 = SubCa::new();
        let cert1 = root.authorize_server(sub_ca1.public_key_bytes(), "srv-1", None);
        sub_ca1.intermediate_cert = Some(cert1);

        let mut sub_ca2 = SubCa::new();
        let cert2 = root.authorize_server(sub_ca2.public_key_bytes(), "srv-2", None);
        sub_ca2.intermediate_cert = Some(cert2);

        let kp = KeyPair::new();
        let client_cert = sub_ca1
            .issue_certificate(kp.public_key_bytes(), "eve")
            .unwrap();

        // Server 2 can't verify Server 1's client cert
        let result = sub_ca2.verify_certificate(&client_cert);
        assert!(!result.valid);
        assert_eq!(result.reason, "issuer_mismatch");
    }
}
