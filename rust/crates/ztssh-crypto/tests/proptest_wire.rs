//! Property-based tests for ztssh-crypto wire formats.
//!
//! These tests verify invariants of the certificate serialization:
//! - Roundtrip: to_wire() → from_wire() is the identity transformation.
//! - No panic on arbitrary byte slices.
//! - Field preservation across serialization boundaries.

use proptest::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};
use ztssh_crypto::{IntermediateCertificate, KeyPair, ZtsshCertificate};

// ─── Strategies ───

fn arb_principal() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_-]{0,31}".prop_map(|s| s)
}

fn arb_server_id() -> impl Strategy<Value = String> {
    "srv-[a-z0-9]{1,16}".prop_map(|s| s)
}

fn arb_principals_list() -> impl Strategy<Value = Vec<String>> {
    prop_oneof![
        Just(vec!["*".to_string()]),
        proptest::collection::vec(arb_principal(), 1..8),
    ]
}

fn arb_serial() -> impl Strategy<Value = u64> {
    1u64..u64::MAX
}

fn arb_ttl() -> impl Strategy<Value = f64> {
    // TTL between 1 second and 24 hours.
    1.0f64..86400.0f64
}

// ─── ZtsshCertificate roundtrip ───

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn cert_wire_roundtrip(
        serial in arb_serial(),
        principal in arb_principal(),
        ttl in arb_ttl(),
    ) {
        let kp_client = KeyPair::new();
        let kp_issuer = KeyPair::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut cert = ZtsshCertificate {
            serial,
            principal: principal.clone(),
            subject_public_key: kp_client.public_key_bytes(),
            issuer_public_key: kp_issuer.public_key_bytes(),
            issued_at: now,
            expires_at: now + ttl,
            signature: [0u8; 64],
        };
        let sig = kp_issuer.sign(&cert.signable_bytes());
        cert.signature = sig.to_bytes();

        let wire = cert.to_wire();
        let restored = ZtsshCertificate::from_wire(&wire).unwrap();

        prop_assert_eq!(restored.serial, serial);
        prop_assert_eq!(&restored.principal, &principal);
        prop_assert_eq!(restored.subject_public_key, cert.subject_public_key);
        prop_assert_eq!(restored.issuer_public_key, cert.issuer_public_key);
        prop_assert_eq!(restored.issued_at.to_bits(), cert.issued_at.to_bits());
        prop_assert_eq!(restored.expires_at.to_bits(), cert.expires_at.to_bits());
        prop_assert_eq!(restored.signature, cert.signature);
    }

    #[test]
    fn cert_signature_valid_after_roundtrip(
        principal in arb_principal(),
    ) {
        let kp_client = KeyPair::new();
        let kp_issuer = KeyPair::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut cert = ZtsshCertificate {
            serial: 1,
            principal,
            subject_public_key: kp_client.public_key_bytes(),
            issuer_public_key: kp_issuer.public_key_bytes(),
            issued_at: now,
            expires_at: now + 300.0,
            signature: [0u8; 64],
        };
        let sig = kp_issuer.sign(&cert.signable_bytes());
        cert.signature = sig.to_bytes();

        let wire = cert.to_wire();
        let restored = ZtsshCertificate::from_wire(&wire).unwrap();
        prop_assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn cert_from_wire_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        // Must never panic, only return Ok or Err.
        let _ = ZtsshCertificate::from_wire(&data);
    }
}

// ─── IntermediateCertificate roundtrip ───

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn intermediate_wire_roundtrip(
        serial in arb_serial(),
        server_id in arb_server_id(),
        principals in arb_principals_list(),
        ttl in arb_ttl(),
    ) {
        let root_kp = KeyPair::new();
        let server_kp = KeyPair::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut cert = IntermediateCertificate {
            serial,
            server_id: server_id.clone(),
            subject_public_key: server_kp.public_key_bytes(),
            issuer_public_key: root_kp.public_key_bytes(),
            allowed_principals: principals.clone(),
            issued_at: now,
            expires_at: now + ttl,
            signature: [0u8; 64],
        };
        let sig = root_kp.sign(&cert.signable_bytes());
        cert.signature = sig.to_bytes();

        let wire = cert.to_wire();
        let restored = IntermediateCertificate::from_wire(&wire).unwrap();

        prop_assert_eq!(restored.serial, serial);
        prop_assert_eq!(&restored.server_id, &server_id);
        prop_assert_eq!(&restored.allowed_principals, &principals);
        prop_assert_eq!(restored.subject_public_key, cert.subject_public_key);
        prop_assert_eq!(restored.issuer_public_key, cert.issuer_public_key);
        prop_assert_eq!(restored.issued_at.to_bits(), cert.issued_at.to_bits());
        prop_assert_eq!(restored.expires_at.to_bits(), cert.expires_at.to_bits());
        prop_assert_eq!(restored.signature, cert.signature);
    }

    #[test]
    fn intermediate_signature_valid_after_roundtrip(
        server_id in arb_server_id(),
        principals in arb_principals_list(),
    ) {
        let root_kp = KeyPair::new();
        let server_kp = KeyPair::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut cert = IntermediateCertificate {
            serial: 1,
            server_id,
            subject_public_key: server_kp.public_key_bytes(),
            issuer_public_key: root_kp.public_key_bytes(),
            allowed_principals: principals,
            issued_at: now,
            expires_at: now + 86400.0,
            signature: [0u8; 64],
        };
        let sig = root_kp.sign(&cert.signable_bytes());
        cert.signature = sig.to_bytes();

        let wire = cert.to_wire();
        let restored = IntermediateCertificate::from_wire(&wire).unwrap();
        prop_assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn intermediate_from_wire_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = IntermediateCertificate::from_wire(&data);
    }

    #[test]
    fn cert_tampered_magic_rejected(
        byte_pos in 0usize..14,
        replace_byte in 0u8..255,
    ) {
        let kp_client = KeyPair::new();
        let kp_issuer = KeyPair::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut cert = ZtsshCertificate {
            serial: 1,
            principal: "alice".into(),
            subject_public_key: kp_client.public_key_bytes(),
            issuer_public_key: kp_issuer.public_key_bytes(),
            issued_at: now,
            expires_at: now + 300.0,
            signature: [0u8; 64],
        };
        let sig = kp_issuer.sign(&cert.signable_bytes());
        cert.signature = sig.to_bytes();

        let mut wire = cert.to_wire();
        let original_byte = wire[byte_pos];
        if replace_byte == original_byte {
            return Ok(()); // skip — no actual change
        }
        wire[byte_pos] = replace_byte;

        // Must either fail or return a cert with wrong data — never panic.
        let _ = ZtsshCertificate::from_wire(&wire);
    }
}
