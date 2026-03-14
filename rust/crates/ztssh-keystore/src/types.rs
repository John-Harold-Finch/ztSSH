//! Keystore types and trait.

use serde::{Deserialize, Serialize};

use crate::error::KeystoreError;

/// What a key is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    /// Root CA signing key.
    RootCa,
    /// Server Sub-CA signing key.
    SubCa,
    /// Client ephemeral session key.
    ClientEphemeral,
}

/// Metadata about a stored key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Unique key identifier.
    pub key_id: String,
    /// Hex-encoded public key.
    pub public_key_hex: String,
    /// Purpose of this key.
    pub purpose: KeyPurpose,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// Optional human-readable label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Trait for key storage backends.
///
/// Implementors must ensure:
/// - Private keys are stored with restricted permissions.
/// - Key material is zeroized when no longer needed.
/// - Operations are atomic where possible.
pub trait Keystore {
    /// Store a key pair with associated metadata.
    fn store(
        &self,
        key_id: &str,
        private_key: &[u8; 32],
        public_key: &[u8; 32],
        purpose: KeyPurpose,
        label: Option<&str>,
    ) -> Result<KeyEntry, KeystoreError>;

    /// Load a private key by ID.
    fn load(&self, key_id: &str) -> Result<[u8; 32], KeystoreError>;

    /// List all stored key entries (metadata only, no private keys).
    fn list(&self) -> Result<Vec<KeyEntry>, KeystoreError>;

    /// Delete a key by ID.
    fn delete(&self, key_id: &str) -> Result<(), KeystoreError>;

    /// Check if a key exists.
    fn exists(&self, key_id: &str) -> bool;
}
