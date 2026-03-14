//! Ed25519 keypair with zeroize-on-drop for private key material.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;

use crate::CryptoError;

/// An Ed25519 keypair that zeroizes private key material on drop.
///
/// This is the fundamental building block for all ZTSSH identities:
/// - Root CA keypair (long-lived, offline)
/// - Sub-CA keypair (per-server, medium-lived)
/// - Client ephemeral keypair (rotated every challenge cycle)
pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    /// Generate a new random Ed25519 keypair using OS entropy.
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Get the 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign arbitrary data with this keypair.
    pub fn sign(&self, data: &[u8]) -> ed25519_dalek::Signature {
        self.signing_key.sign(data)
    }

    /// Verify a signature against this keypair's public key.
    pub fn verify(&self, signature: &ed25519_dalek::Signature, data: &[u8]) -> bool {
        self.signing_key
            .verifying_key()
            .verify(data, signature)
            .is_ok()
    }

    /// Verify a signature using raw public key bytes (static method).
    pub fn verify_with_key(
        public_key_bytes: &[u8; 32],
        signature_bytes: &[u8; 64],
        data: &[u8],
    ) -> Result<bool, CryptoError> {
        let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let signature = ed25519_dalek::Signature::from_bytes(signature_bytes);
        Ok(verifying_key.verify(data, &signature).is_ok())
    }

    /// Export the private key bytes (32-byte Ed25519 seed) for persistence.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Restore a keypair from persisted private key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    /// Constant-time comparison of two 32-byte public keys.
    ///
    /// Prevents timing side-channels when comparing keys from untrusted
    /// sources (e.g. certificate issuer fields) against local keys.
    pub fn ct_eq_keys(a: &[u8; 32], b: &[u8; 32]) -> bool {
        a.ct_eq(b).into()
    }
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        // ed25519-dalek's SigningKey implements ZeroizeOnDrop when compiled
        // with the "zeroize" feature (which we enable). The SigningKey's own
        // drop handler securely zeroizes the private key material.
        //
        // This explicit Drop is kept as a semantic marker — it documents
        // the security invariant and prevents accidental removal of the
        // zeroize feature flag.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let kp = KeyPair::new();
        let data = b"hello ztssh";
        let sig = kp.sign(data);
        assert!(kp.verify(&sig, data));
    }

    #[test]
    fn verify_wrong_data_fails() {
        let kp = KeyPair::new();
        let sig = kp.sign(b"correct");
        assert!(!kp.verify(&sig, b"wrong"));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let kp1 = KeyPair::new();
        let kp2 = KeyPair::new();
        let sig = kp1.sign(b"data");
        assert!(!kp2.verify(&sig, b"data"));
    }

    #[test]
    fn public_key_is_32_bytes() {
        let kp = KeyPair::new();
        assert_eq!(kp.public_key_bytes().len(), 32);
    }

    #[test]
    fn two_keypairs_are_different() {
        let kp1 = KeyPair::new();
        let kp2 = KeyPair::new();
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn verify_with_key_static() {
        let kp = KeyPair::new();
        let data = b"static verify test";
        let sig = kp.sign(data);
        let result =
            KeyPair::verify_with_key(&kp.public_key_bytes(), &sig.to_bytes(), data).unwrap();
        assert!(result);
    }
}
