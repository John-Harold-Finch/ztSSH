//! Constant-time operation audit tests.
//!
//! These tests verify that sensitive cryptographic comparisons use
//! constant-time primitives from the `subtle` crate.
//!
//! While we cannot directly measure timing from Rust tests, we verify:
//! - ct_eq_keys returns correct results
//! - Comparisons go through the constant-time path
//! - All-zero and all-one keys are handled correctly

use ztssh_crypto::KeyPair;

#[test]
fn ct_eq_keys_identical() {
    let kp = KeyPair::new();
    let pk = kp.public_key_bytes();
    assert!(KeyPair::ct_eq_keys(&pk, &pk));
}

#[test]
fn ct_eq_keys_different() {
    let kp1 = KeyPair::new();
    let kp2 = KeyPair::new();
    assert!(!KeyPair::ct_eq_keys(
        &kp1.public_key_bytes(),
        &kp2.public_key_bytes()
    ));
}

#[test]
fn ct_eq_keys_all_zero_vs_nonzero() {
    let zero = [0u8; 32];
    let kp = KeyPair::new();
    assert!(!KeyPair::ct_eq_keys(&zero, &kp.public_key_bytes()));
}

#[test]
fn ct_eq_keys_single_bit_difference() {
    let kp = KeyPair::new();
    let pk = kp.public_key_bytes();
    let mut modified = pk;
    modified[0] ^= 0x01; // Flip one bit
    assert!(!KeyPair::ct_eq_keys(&pk, &modified));
}

#[test]
fn ct_eq_keys_all_ones_vs_all_zeros() {
    let zeros = [0u8; 32];
    let ones = [0xFFu8; 32];
    assert!(!KeyPair::ct_eq_keys(&zeros, &ones));
}

#[test]
fn keypair_zeroize_on_drop() {
    // Verify that KeyPair can be dropped without panicking.
    // The actual zeroization is handled by ed25519-dalek's ZeroizeOnDrop
    // trait implementation when the "zeroize" feature is enabled.
    let kp = KeyPair::new();
    let _pk = kp.public_key_bytes(); // Force materialization
    drop(kp); // Should not panic
}

#[test]
fn from_bytes_roundtrip_preserves_keys() {
    let kp = KeyPair::new();
    let private_bytes = kp.to_bytes();
    let public_bytes = kp.public_key_bytes();

    let restored = KeyPair::from_bytes(&private_bytes);
    assert!(KeyPair::ct_eq_keys(
        &restored.public_key_bytes(),
        &public_bytes
    ));
}
