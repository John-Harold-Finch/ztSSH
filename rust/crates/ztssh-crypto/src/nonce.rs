//! Cryptographically secure nonce generation.

use rand::RngCore;

/// Default nonce length in bytes.
pub const DEFAULT_NONCE_LEN: usize = 32;

/// Generate a cryptographically secure random nonce.
///
/// Uses the OS CSPRNG (`/dev/urandom` on Linux, `BCryptGenRandom` on Windows).
///
/// # Arguments
/// * `len` — Number of random bytes (default: 32).
pub fn generate_nonce(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn nonce_default_length() {
        let n = generate_nonce(DEFAULT_NONCE_LEN);
        assert_eq!(n.len(), 32);
    }

    #[test]
    fn nonce_custom_length() {
        assert_eq!(generate_nonce(64).len(), 64);
        assert_eq!(generate_nonce(16).len(), 16);
    }

    #[test]
    fn nonce_uniqueness() {
        let nonces: HashSet<Vec<u8>> = (0..100).map(|_| generate_nonce(32)).collect();
        assert_eq!(nonces.len(), 100, "100 nonces should all be unique");
    }
}
