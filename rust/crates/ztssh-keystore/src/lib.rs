//! # ztssh-keystore
//!
//! Secure key storage for ZTSSH.
//!
//! Provides a filesystem-backed keystore for Ed25519 private keys with:
//! - Restricted file permissions (0600 on Unix)
//! - Metadata tracking (key ID, creation time, purpose)
//! - Zeroization of in-memory key material on drop
//! - Pluggable backend trait for future HSM/agent integration

mod error;
mod filesystem;
mod types;

pub use error::KeystoreError;
pub use filesystem::FilesystemKeystore;
pub use types::{KeyEntry, KeyPurpose, Keystore};
