//! # ztssh-crypto
//!
//! Cryptographic primitives for the ZTSSH protocol.
//!
//! - **Ed25519** keypairs with automatic zeroization of private keys
//! - **ZTSSHCertificate** — short-lived client badge (5 min TTL)
//! - **IntermediateCertificate** — server licence from Root CA (24h TTL)
//! - Challenge signing / verification
//! - Cryptographically secure nonce generation

mod certificate;
mod error;
mod intermediate;
mod keypair;
mod nonce;

pub use certificate::ZtsshCertificate;
pub use error::CryptoError;
pub use intermediate::IntermediateCertificate;
pub use keypair::KeyPair;
pub use nonce::{generate_nonce, DEFAULT_NONCE_LEN};

/// Re-export for convenience.
pub use ed25519_dalek::{Signature, VerifyingKey};
