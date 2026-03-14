//! Property-based tests for the CA layer.
//!
//! Verifies invariants of certificate issuance, verification, and revocation.

use proptest::prelude::*;
use ztssh_ca::{RootCa, SubCa};
use ztssh_crypto::KeyPair;

fn arb_principal() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,15}".prop_map(|s| s)
}

fn arb_server_id() -> impl Strategy<Value = String> {
    "srv-[a-z0-9]{1,8}".prop_map(|s| s)
}

/// Helper: create an authorized Sub-CA with wildcard principals.
fn make_authorized_sub_ca(root: &RootCa, server_kp: KeyPair, server_id: &str) -> SubCa {
    let intermediate = root.authorize_server(
        server_kp.public_key_bytes(),
        server_id,
        None,
    );
    let mut sub_ca = SubCa::from_keypair(server_kp);
    sub_ca.intermediate_cert = Some(intermediate);
    sub_ca.root_public_key = Some(root.public_key_bytes());
    sub_ca
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// A certificate issued by a properly authorized Sub-CA should always
    /// verify successfully.
    #[test]
    fn issued_cert_always_verifiable(
        principal in arb_principal(),
        server_id in arb_server_id(),
    ) {
        let root = RootCa::new();
        let server_kp = KeyPair::new();
        let client_kp = KeyPair::new();

        let sub_ca = make_authorized_sub_ca(&root, server_kp, &server_id);

        let cert = sub_ca.issue_certificate(
            client_kp.public_key_bytes(),
            &principal,
        ).unwrap();

        let result = sub_ca.verify_certificate(&cert);
        prop_assert!(result.valid, "verification failed: {}", result.reason);
        prop_assert_eq!(result.principal.as_deref(), Some(principal.as_str()));
    }

    /// A certificate issued by Sub-CA A should NOT verify under Sub-CA B.
    #[test]
    fn cert_from_wrong_issuer_rejected(
        principal in arb_principal(),
    ) {
        let root = RootCa::new();

        // Sub-CA A: authorized, issues cert
        let server_kp_a = KeyPair::new();
        let sub_ca_a = make_authorized_sub_ca(&root, server_kp_a, "srv-a");

        let client_kp = KeyPair::new();
        let cert = sub_ca_a.issue_certificate(
            client_kp.public_key_bytes(),
            &principal,
        ).unwrap();

        // Sub-CA B: different keypair
        let server_kp_b = KeyPair::new();
        let sub_ca_b = make_authorized_sub_ca(&root, server_kp_b, "srv-b");

        let result = sub_ca_b.verify_certificate(&cert);
        prop_assert!(!result.valid, "cross-issuer cert should not verify");
    }

    /// Revoking a client cert serial causes verification to fail.
    #[test]
    fn revoked_cert_rejected(
        principal in arb_principal(),
    ) {
        let root = RootCa::new();
        let server_kp = KeyPair::new();
        let client_kp = KeyPair::new();

        let mut sub_ca = make_authorized_sub_ca(&root, server_kp, "srv-revoke");

        let cert = sub_ca.issue_certificate(
            client_kp.public_key_bytes(),
            &principal,
        ).unwrap();

        // Revoke the certificate
        sub_ca.revoke_client(cert.serial);

        let result = sub_ca.verify_certificate(&cert);
        prop_assert!(!result.valid, "revoked cert should not verify");
    }

    /// Banning a principal causes all certs for that principal to fail verification.
    #[test]
    fn banned_principal_rejected(
        principal in arb_principal(),
    ) {
        let root = RootCa::new();
        let server_kp = KeyPair::new();
        let client_kp = KeyPair::new();

        let mut sub_ca = make_authorized_sub_ca(&root, server_kp, "srv-ban");

        let cert = sub_ca.issue_certificate(
            client_kp.public_key_bytes(),
            &principal,
        ).unwrap();

        // Ban the principal via the revocation list
        sub_ca.revocation_list.ban_principal(&principal);

        let result = sub_ca.verify_certificate(&cert);
        prop_assert!(!result.valid, "banned principal cert should not verify");
    }

    /// A restricted Sub-CA cannot issue certs for principals outside its scope.
    #[test]
    fn restricted_ca_rejects_unauthorized_principal(
        principal in arb_principal(),
    ) {
        let root = RootCa::new();
        let server_kp = KeyPair::new();
        let client_kp = KeyPair::new();

        // Authorize only for "allowed-user", not for the random principal
        let intermediate = root.authorize_server(
            server_kp.public_key_bytes(),
            "srv-restricted",
            Some(vec!["allowed-user".to_string()]),
        );
        let mut sub_ca = SubCa::from_keypair(server_kp);
        sub_ca.intermediate_cert = Some(intermediate);
        sub_ca.root_public_key = Some(root.public_key_bytes());

        if principal == "allowed-user" {
            let cert = sub_ca.issue_certificate(
                client_kp.public_key_bytes(),
                &principal,
            );
            prop_assert!(cert.is_ok());
        } else {
            let cert = sub_ca.issue_certificate(
                client_kp.public_key_bytes(),
                &principal,
            );
            prop_assert!(cert.is_err());
        }
    }

    /// Intermediate cert signature is always valid when issued by Root CA.
    #[test]
    fn intermediate_always_verifiable(
        server_id in arb_server_id(),
    ) {
        let root = RootCa::new();
        let server_kp = KeyPair::new();

        let intermediate = root.authorize_server(
            server_kp.public_key_bytes(),
            &server_id,
            None,
        );

        prop_assert!(intermediate.verify_signature().unwrap());
        let result = root.verify_intermediate(&intermediate);
        prop_assert!(result.valid);
    }
}
