//! Filesystem-backed keystore.
//!
//! Layout:
//! ```text
//! <base_dir>/
//!   keys.json          — metadata index (KeyEntry list)
//!   keys/
//!     <key_id>.key     — 32-byte raw Ed25519 private key (mode 0600)
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;

use crate::error::KeystoreError;
use crate::types::{KeyEntry, KeyPurpose, Keystore};

/// A filesystem-backed keystore with restricted file permissions.
pub struct FilesystemKeystore {
    base_dir: PathBuf,
}

impl FilesystemKeystore {
    /// Create or open a keystore at the given directory.
    pub fn open(base_dir: impl Into<PathBuf>) -> Result<Self, KeystoreError> {
        let base_dir = base_dir.into();
        fs::create_dir_all(base_dir.join("keys"))?;

        // Ensure index file exists
        let index_path = base_dir.join("keys.json");
        if !index_path.exists() {
            fs::write(&index_path, "[]")?;
        }

        Ok(Self { base_dir })
    }

    /// Get the base directory.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    fn index_path(&self) -> PathBuf {
        self.base_dir.join("keys.json")
    }

    fn key_path(&self, key_id: &str) -> PathBuf {
        self.base_dir.join("keys").join(format!("{}.key", key_id))
    }

    fn read_index(&self) -> Result<Vec<KeyEntry>, KeystoreError> {
        let data = fs::read_to_string(self.index_path())?;
        serde_json::from_str(&data).map_err(|e| KeystoreError::Serialization(e.to_string()))
    }

    fn write_index(&self, entries: &[KeyEntry]) -> Result<(), KeystoreError> {
        let json = serde_json::to_string_pretty(entries)
            .map_err(|e| KeystoreError::Serialization(e.to_string()))?;
        fs::write(self.index_path(), json)?;
        Ok(())
    }

    /// Restrict file permissions to owner-only on Unix.
    #[cfg(unix)]
    fn restrict_permissions(path: &Path) -> Result<(), KeystoreError> {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)?;
        Ok(())
    }

    /// On non-Unix systems, permission restriction is a no-op (best effort).
    #[cfg(not(unix))]
    fn restrict_permissions(_path: &Path) -> Result<(), KeystoreError> {
        Ok(())
    }
}

impl Keystore for FilesystemKeystore {
    fn store(
        &self,
        key_id: &str,
        private_key: &[u8; 32],
        public_key: &[u8; 32],
        purpose: KeyPurpose,
        label: Option<&str>,
    ) -> Result<KeyEntry, KeystoreError> {
        let key_path = self.key_path(key_id);
        if key_path.exists() {
            return Err(KeystoreError::AlreadyExists(key_id.to_string()));
        }

        // Write private key with restricted permissions
        fs::write(&key_path, private_key)?;
        Self::restrict_permissions(&key_path)?;

        let entry = KeyEntry {
            key_id: key_id.to_string(),
            public_key_hex: hex::encode(public_key),
            purpose,
            created_at: Utc::now().to_rfc3339(),
            label: label.map(|s| s.to_string()),
        };

        let mut index = self.read_index()?;
        index.push(entry.clone());
        self.write_index(&index)?;

        Ok(entry)
    }

    fn load(&self, key_id: &str) -> Result<[u8; 32], KeystoreError> {
        let key_path = self.key_path(key_id);
        if !key_path.exists() {
            return Err(KeystoreError::NotFound(key_id.to_string()));
        }

        let bytes = fs::read(&key_path)?;
        let key: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            KeystoreError::InvalidKeyData(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Ok(key)
    }

    fn list(&self) -> Result<Vec<KeyEntry>, KeystoreError> {
        self.read_index()
    }

    fn delete(&self, key_id: &str) -> Result<(), KeystoreError> {
        let key_path = self.key_path(key_id);
        if !key_path.exists() {
            return Err(KeystoreError::NotFound(key_id.to_string()));
        }

        // Overwrite with zeros before deleting
        let zeros = [0u8; 32];
        fs::write(&key_path, zeros)?;
        fs::remove_file(&key_path)?;

        // Remove from index
        let mut index = self.read_index()?;
        index.retain(|e| e.key_id != key_id);
        self.write_index(&index)?;

        Ok(())
    }

    fn exists(&self, key_id: &str) -> bool {
        self.key_path(key_id).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_keystore() -> (tempfile::TempDir, FilesystemKeystore) {
        let dir = tempfile::tempdir().unwrap();
        let ks = FilesystemKeystore::open(dir.path()).unwrap();
        (dir, ks)
    }

    #[test]
    fn store_and_load() {
        let (_dir, ks) = temp_keystore();
        let priv_key = [42u8; 32];
        let pub_key = [7u8; 32];

        let entry = ks
            .store(
                "test-key",
                &priv_key,
                &pub_key,
                KeyPurpose::SubCa,
                Some("demo"),
            )
            .unwrap();
        assert_eq!(entry.key_id, "test-key");
        assert_eq!(entry.purpose, KeyPurpose::SubCa);
        assert_eq!(entry.label.as_deref(), Some("demo"));

        let loaded = ks.load("test-key").unwrap();
        assert_eq!(loaded, priv_key);
    }

    #[test]
    fn list_keys() {
        let (_dir, ks) = temp_keystore();
        ks.store("key-a", &[1u8; 32], &[2u8; 32], KeyPurpose::RootCa, None)
            .unwrap();
        ks.store("key-b", &[3u8; 32], &[4u8; 32], KeyPurpose::SubCa, None)
            .unwrap();

        let entries = ks.list().unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn delete_key() {
        let (_dir, ks) = temp_keystore();
        ks.store(
            "del-me",
            &[5u8; 32],
            &[6u8; 32],
            KeyPurpose::ClientEphemeral,
            None,
        )
        .unwrap();
        assert!(ks.exists("del-me"));

        ks.delete("del-me").unwrap();
        assert!(!ks.exists("del-me"));
        assert!(ks.load("del-me").is_err());
    }

    #[test]
    fn duplicate_key_rejected() {
        let (_dir, ks) = temp_keystore();
        ks.store("dup", &[1u8; 32], &[2u8; 32], KeyPurpose::SubCa, None)
            .unwrap();

        let result = ks.store("dup", &[3u8; 32], &[4u8; 32], KeyPurpose::SubCa, None);
        assert!(result.is_err());
    }

    #[test]
    fn load_missing_key() {
        let (_dir, ks) = temp_keystore();
        assert!(ks.load("nonexistent").is_err());
    }
}
