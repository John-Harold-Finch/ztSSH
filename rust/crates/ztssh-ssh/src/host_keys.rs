//! SSH host key management — generate Ed25519 host keys for russh.

use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::{Algorithm, PrivateKey};

use crate::error::SshTransportError;

/// Generate a new Ed25519 SSH host key.
///
/// The returned key can be placed directly into `russh::server::Config::keys`.
pub fn generate_host_key() -> Result<PrivateKey, SshTransportError> {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| SshTransportError::Other(format!("key generation failed: {e}")))
}
