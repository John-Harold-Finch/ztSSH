//! Property-based tests for protocol message serialization.
//!
//! Verifies roundtrip invariants for all four message types and ensures
//! deserializers never panic on arbitrary input.

use proptest::prelude::*;
use ztssh_crypto::generate_nonce;
use ztssh_protocol::{
    IdentityAck, IdentityChallenge, IdentityProof, SessionTerminate, TerminateReason,
};

fn arb_nonce() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 1..128)
}

fn arb_cert_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 1..512)
}

fn arb_sig_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 1..128)
}

fn arb_terminate_reason() -> impl Strategy<Value = TerminateReason> {
    prop_oneof![
        Just(TerminateReason::CertExpired),
        Just(TerminateReason::CertRevoked),
        Just(TerminateReason::ChallengeTimeout),
        Just(TerminateReason::InvalidProof),
        Just(TerminateReason::PolicyViolation),
        Just(TerminateReason::AdminRevoke),
        Just(TerminateReason::PrincipalBanned),
    ]
}

fn arb_reason_message() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 ._-]{0,128}".prop_map(|s| s)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    // ─── IdentityChallenge ───

    #[test]
    fn challenge_roundtrip(
        seq in any::<u32>(),
        ts in any::<u64>(),
        nonce in arb_nonce(),
        deadline in 1u32..3600,
    ) {
        let msg = IdentityChallenge {
            sequence_number: seq,
            timestamp: ts,
            nonce: nonce.clone(),
            deadline_seconds: deadline,
        };
        let data = msg.serialize();
        let restored = IdentityChallenge::deserialize(&data).unwrap();

        prop_assert_eq!(restored.sequence_number, seq);
        prop_assert_eq!(restored.timestamp, ts);
        prop_assert_eq!(&restored.nonce, &nonce);
        prop_assert_eq!(restored.deadline_seconds, deadline);
    }

    #[test]
    fn challenge_deserialize_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = IdentityChallenge::deserialize(&data);
    }

    // ─── IdentityProof ───

    #[test]
    fn proof_roundtrip(
        seq in any::<u32>(),
        ts in any::<u64>(),
        cert in arb_cert_bytes(),
        sig in arb_sig_bytes(),
    ) {
        let msg = IdentityProof {
            sequence_number: seq,
            timestamp: ts,
            certificate: cert.clone(),
            signature: sig.clone(),
        };
        let data = msg.serialize();
        let restored = IdentityProof::deserialize(&data).unwrap();

        prop_assert_eq!(restored.sequence_number, seq);
        prop_assert_eq!(restored.timestamp, ts);
        prop_assert_eq!(&restored.certificate, &cert);
        prop_assert_eq!(&restored.signature, &sig);
    }

    #[test]
    fn proof_deserialize_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = IdentityProof::deserialize(&data);
    }

    // ─── IdentityAck ───

    #[test]
    fn ack_roundtrip(
        seq in any::<u32>(),
        next in any::<u32>(),
    ) {
        let msg = IdentityAck {
            sequence_number: seq,
            next_challenge_in_seconds: next,
        };
        let data = msg.serialize();
        let restored = IdentityAck::deserialize(&data).unwrap();

        prop_assert_eq!(restored.sequence_number, seq);
        prop_assert_eq!(restored.next_challenge_in_seconds, next);
    }

    #[test]
    fn ack_deserialize_never_panics(data in proptest::collection::vec(any::<u8>(), 0..64)) {
        let _ = IdentityAck::deserialize(&data);
    }

    // ─── SessionTerminate ───

    #[test]
    fn terminate_roundtrip(
        seq in any::<u32>(),
        reason in arb_terminate_reason(),
        message in arb_reason_message(),
    ) {
        let msg = SessionTerminate {
            sequence_number: seq,
            reason_code: reason,
            reason_message: message.clone(),
        };
        let data = msg.serialize();
        let restored = SessionTerminate::deserialize(&data).unwrap();

        prop_assert_eq!(restored.sequence_number, seq);
        prop_assert_eq!(restored.reason_code, reason);
        prop_assert_eq!(&restored.reason_message, &message);
    }

    #[test]
    fn terminate_deserialize_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = SessionTerminate::deserialize(&data);
    }

    // ─── Cross-message type dispatch ───

    #[test]
    fn wrong_msg_type_rejected(
        data in proptest::collection::vec(any::<u8>(), 17..256),
    ) {
        // Replace the first byte with an invalid message type and verify
        // each parser rejects it.
        let mut buf = data.clone();
        buf[0] = 0xFF; // Invalid type

        prop_assert!(IdentityChallenge::deserialize(&buf).is_err());
        prop_assert!(IdentityProof::deserialize(&buf).is_err());
        prop_assert!(IdentityAck::deserialize(&buf).is_err());
        prop_assert!(SessionTerminate::deserialize(&buf).is_err());
    }

    // ─── Nonce uniqueness property ───

    #[test]
    fn nonces_are_unique(_seed in any::<u64>()) {
        let n1 = generate_nonce(32);
        let n2 = generate_nonce(32);
        prop_assert_ne!(n1, n2);
    }
}
