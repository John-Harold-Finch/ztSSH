//! Property-based tests for transport-layer handshake messages.
//!
//! Verifies roundtrip invariants for handshake message builders/parsers.

use proptest::prelude::*;
use ztssh_crypto::{KeyPair, ZtsshCertificate};
use ztssh_transport::server::{
    build_cert_renewal_request, build_client_hello, build_server_hello,
    parse_cert_renewal_response, parse_client_hello, parse_server_hello,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn arb_principal() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_-]{0,31}".prop_map(|s| s)
}

/// Helper: build a valid signed ZtsshCertificate.
fn make_cert(principal: &str) -> (KeyPair, ZtsshCertificate) {
    let kp_client = KeyPair::new();
    let kp_issuer = KeyPair::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();

    let mut cert = ZtsshCertificate {
        serial: 1,
        principal: principal.to_string(),
        subject_public_key: kp_client.public_key_bytes(),
        issuer_public_key: kp_issuer.public_key_bytes(),
        issued_at: now,
        expires_at: now + 300.0,
        signature: [0u8; 64],
    };
    let sig = kp_issuer.sign(&cert.signable_bytes());
    cert.signature = sig.to_bytes();
    (kp_client, cert)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn client_hello_roundtrip(principal in arb_principal()) {
        let kp = KeyPair::new();
        let pk = kp.public_key_bytes();
        let msg = build_client_hello(&principal, &pk);
        let (restored_principal, restored_pk) = parse_client_hello(&msg).unwrap();

        prop_assert_eq!(&restored_principal, &principal);
        prop_assert_eq!(restored_pk, pk);
    }

    #[test]
    fn server_hello_roundtrip(principal in arb_principal()) {
        let (_, cert) = make_cert(&principal);
        let msg = build_server_hello(&cert);
        let restored = parse_server_hello(&msg).unwrap();

        prop_assert_eq!(restored.serial, cert.serial);
        prop_assert_eq!(&restored.principal, &cert.principal);
        prop_assert_eq!(restored.subject_public_key, cert.subject_public_key);
        prop_assert_eq!(restored.signature, cert.signature);
    }

    #[test]
    fn cert_renewal_request_roundtrip(principal in arb_principal()) {
        let kp = KeyPair::new();
        let pk = kp.public_key_bytes();
        let msg = build_cert_renewal_request(&principal, &pk);

        // Renewal request parser returns (pk, principal)
        use ztssh_transport::server::parse_cert_renewal_request_v2;
        let (restored_pk, restored_principal) = parse_cert_renewal_request_v2(&msg).unwrap();

        prop_assert_eq!(&restored_principal, &principal);
        prop_assert_eq!(restored_pk, pk);
    }

    #[test]
    fn client_hello_parse_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_client_hello(&data);
    }

    #[test]
    fn server_hello_parse_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_server_hello(&data);
    }

    #[test]
    fn cert_renewal_response_parse_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_cert_renewal_response(&data);
    }
}
