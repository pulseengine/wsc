pub use crate::error::*;
use crate::secure_file;

use ct_codecs::{Encoder, Hex};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, prelude::*};
use std::path::Path;
use std::fmt;

pub(crate) const ED25519_PK_ID: u8 = 0x01;
pub(crate) const ED25519_SK_ID: u8 = 0x81;

/// A public key.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct PublicKey {
    pub pk: ed25519_compact::PublicKey,
    pub key_id: Option<Vec<u8>>,
}

impl PublicKey {
    /// Create a public key from raw bytes.
    pub fn from_bytes(pk: &[u8]) -> Result<Self, WSError> {
        let mut reader = io::Cursor::new(pk);
        let mut id = [0u8];
        reader.read_exact(&mut id)?;
        if id[0] != ED25519_PK_ID {
            return Err(WSError::UnsupportedKeyType);
        }
        let mut bytes = vec![];
        reader.read_to_end(&mut bytes)?;
        Ok(Self {
            pk: ed25519_compact::PublicKey::from_slice(&bytes)?,
            key_id: None,
        })
    }

    /// Deserialize a PEM-encoded public key.
    pub fn from_pem(pem: &str) -> Result<Self, WSError> {
        let pk = ed25519_compact::PublicKey::from_pem(pem)?;
        Ok(Self { pk, key_id: None })
    }

    /// Deserialize a DER-encoded public key.
    pub fn from_der(der: &[u8]) -> Result<Self, WSError> {
        let pk = ed25519_compact::PublicKey::from_der(der)?;
        Ok(Self { pk, key_id: None })
    }

    /// Return the public key as raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![ED25519_PK_ID];
        bytes.extend_from_slice(self.pk.as_ref());
        bytes
    }

    /// Serialize the public key using PEM encoding.
    pub fn to_pem(&self) -> String {
        self.pk.to_pem()
    }

    /// Serialize the public key using DER encoding.
    pub fn to_der(&self) -> Vec<u8> {
        self.pk.to_der()
    }

    /// Read public key from a file.
    pub fn from_file(file: impl AsRef<Path>) -> Result<Self, WSError> {
        let mut fp = File::open(file)?;
        let mut bytes = vec![];
        fp.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    /// Save the public key to a file.
    pub fn to_file(&self, file: impl AsRef<Path>) -> Result<(), WSError> {
        let mut fp = File::create(file)?;
        fp.write_all(&self.to_bytes())?;
        Ok(())
    }

    /// Return the key identifier associated with this public key, if there is one.
    pub fn key_id(&self) -> Option<&Vec<u8>> {
        self.key_id.as_ref()
    }

    /// Compute a deterministic key identifier for this public key, if it doesn't already have one.
    pub fn attach_default_key_id(mut self) -> Self {
        if self.key_id.is_none() {
            self.key_id = Some(hmac_sha256::HMAC::mac(b"key_id", self.pk.as_ref())[0..12].to_vec());
        }
        self
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PublicKey {{ [{}] - key_id: {:?} }}",
            Hex::encode_to_string(self.pk.as_ref()).unwrap_or_else(|_| "<hex error>".to_string()),
            self.key_id()
                .map(|key_id| format!("[{}]", Hex::encode_to_string(key_id).unwrap_or_else(|_| "<hex error>".to_string())))
        )
    }
}

/// A secret key.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct SecretKey {
    pub sk: ed25519_compact::SecretKey,
}

impl SecretKey {
    /// Create a secret key from raw bytes.
    pub fn from_bytes(sk: &[u8]) -> Result<Self, WSError> {
        let mut reader = io::Cursor::new(sk);
        let mut id = [0u8];
        reader.read_exact(&mut id)?;
        if id[0] != ED25519_SK_ID {
            return Err(WSError::UnsupportedKeyType);
        }
        let mut bytes = vec![];
        reader.read_to_end(&mut bytes)?;
        Ok(Self {
            sk: ed25519_compact::SecretKey::from_slice(&bytes)?,
        })
    }

    /// Deserialize a PEM-encoded secret key.
    pub fn from_pem(pem: &str) -> Result<Self, WSError> {
        let sk = ed25519_compact::SecretKey::from_pem(pem)?;
        Ok(Self { sk })
    }

    /// Deserialize a DER-encoded secret key.
    pub fn from_der(der: &[u8]) -> Result<Self, WSError> {
        let sk = ed25519_compact::SecretKey::from_der(der)?;
        Ok(Self { sk })
    }

    /// Return the secret key as raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![ED25519_SK_ID];
        bytes.extend_from_slice(self.sk.as_ref());
        bytes
    }

    /// Serialize the secret key using PEM encoding.
    pub fn to_pem(&self) -> String {
        self.sk.to_pem()
    }

    /// Serialize the secret key using DER encoding.
    pub fn to_der(&self) -> Vec<u8> {
        self.sk.to_der()
    }

    /// Read a secret key from a file.
    ///
    /// # Security
    ///
    /// On Unix systems, this function checks file permissions and logs a warning
    /// if the file is readable by group or others. Secret keys should have mode
    /// 0600 (owner read/write only) to prevent credential theft.
    pub fn from_file(file: impl AsRef<Path>) -> Result<Self, WSError> {
        let bytes = secure_file::read_secure(file.as_ref())?;
        Self::from_bytes(&bytes)
    }

    /// Save a secret key to a file.
    ///
    /// # Security
    ///
    /// On Unix systems, this function creates the file with mode 0600
    /// (owner read/write only) to prevent credential theft. The restrictive
    /// permissions are set atomically when the file is created, so there is
    /// no window where the file is accessible to other users.
    ///
    /// On non-Unix systems, a warning is logged that permissions cannot be
    /// enforced, and the file is created with default permissions.
    pub fn to_file(&self, file: impl AsRef<Path>) -> Result<(), WSError> {
        secure_file::write_secure(file.as_ref(), &self.to_bytes())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // SECURITY: Never expose secret key material in debug output
        // Keys could leak through logs, panic messages, or error traces
        write!(f, "SecretKey {{ [REDACTED] }}")
    }
}

/// A key pair.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct KeyPair {
    /// The public key.
    pub pk: PublicKey,
    /// The secret key.
    pub sk: SecretKey,
}

impl KeyPair {
    /// Generate a new key pair.
    pub fn generate() -> Self {
        let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::generate());
        KeyPair {
            pk: PublicKey {
                pk: kp.pk,
                key_id: None,
            },
            sk: SecretKey { sk: kp.sk },
        }
    }
}

/// A set of multiple public keys.
#[derive(Debug, Clone)]
pub struct PublicKeySet {
    pub pks: HashSet<PublicKey>,
}

impl PublicKeySet {
    /// Create an empty public key set.
    pub fn empty() -> Self {
        PublicKeySet {
            pks: HashSet::new(),
        }
    }

    /// Create a new public key set.
    pub fn new(pks: HashSet<PublicKey>) -> Self {
        PublicKeySet { pks }
    }

    /// Return the number of keys in the set.
    pub fn len(&self) -> usize {
        self.pks.len()
    }

    /// Return true if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.pks.is_empty()
    }

    /// Add a public key to the set.
    pub fn insert(&mut self, pk: PublicKey) -> Result<(), WSError> {
        if !self.pks.insert(pk) {
            return Err(WSError::DuplicatePublicKey);
        }
        Ok(())
    }

    /// Merge another public key set into this one.
    pub fn merge(&mut self, other: &PublicKeySet) -> Result<(), WSError> {
        for pk in other.pks.iter() {
            self.insert(pk.clone())?;
        }
        Ok(())
    }

    /// Remove a key from the set.
    pub fn remove(&mut self, pk: &PublicKey) -> Result<(), WSError> {
        if !self.pks.remove(pk) {
            return Err(WSError::UnknownPublicKey);
        }
        Ok(())
    }

    /// Return the hash set storing the keys.
    pub fn items(&self) -> &HashSet<PublicKey> {
        &self.pks
    }

    /// Return the mutable hash set storing the keys.
    pub fn items_mut(&mut self) -> &mut HashSet<PublicKey> {
        &mut self.pks
    }

    /// Add a deterministic key identifier to all the keys that don't have one already.
    pub fn attach_default_key_id(mut self) -> Self {
        self.pks = self
            .pks
            .into_iter()
            .map(|pk| pk.attach_default_key_id())
            .collect();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate()
    }

    #[test]
    fn test_keypair_generate() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        // Different keypairs should have different public keys
        assert_ne!(kp1.pk.pk.as_ref(), kp2.pk.pk.as_ref());
    }

    #[test]
    fn test_public_key_to_from_bytes() {
        let kp = create_test_keypair();
        let bytes = kp.pk.to_bytes();

        assert_eq!(bytes[0], ED25519_PK_ID);

        let pk2 = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk2.pk.as_ref(), kp.pk.pk.as_ref());
    }

    #[test]
    fn test_public_key_invalid_type() {
        let bytes = vec![0xFF, 1, 2, 3, 4]; // Invalid key type
        let result = PublicKey::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::UnsupportedKeyType));
    }

    #[test]
    fn test_public_key_to_from_pem() {
        let kp = create_test_keypair();
        let pem = kp.pk.to_pem();

        assert!(pem.contains("PUBLIC KEY"));

        let pk2 = PublicKey::from_pem(&pem).unwrap();
        assert_eq!(pk2.pk.as_ref(), kp.pk.pk.as_ref());
    }

    #[test]
    fn test_public_key_to_from_der() {
        let kp = create_test_keypair();
        let der = kp.pk.to_der();

        assert!(!der.is_empty());

        let pk2 = PublicKey::from_der(&der).unwrap();
        assert_eq!(pk2.pk.as_ref(), kp.pk.pk.as_ref());
    }

    #[test]
    fn test_public_key_attach_default_key_id() {
        let kp = create_test_keypair();
        let pk_without_id = kp.pk.clone();
        assert!(pk_without_id.key_id().is_none());

        let pk_with_id = pk_without_id.attach_default_key_id();
        assert!(pk_with_id.key_id().is_some());
        assert_eq!(pk_with_id.key_id().unwrap().len(), 12);
    }

    #[test]
    fn test_public_key_attach_default_key_id_idempotent() {
        let kp = create_test_keypair();
        let pk1 = kp.pk.attach_default_key_id();
        let key_id1 = pk1.key_id().unwrap().clone();

        let pk2 = pk1.attach_default_key_id();
        let key_id2 = pk2.key_id().unwrap().clone();

        assert_eq!(key_id1, key_id2);
    }

    #[test]
    fn test_public_key_debug() {
        let kp = create_test_keypair();
        let debug_str = format!("{:?}", kp.pk);
        assert!(debug_str.contains("PublicKey"));
    }

    #[test]
    fn test_secret_key_to_from_bytes() {
        let kp = create_test_keypair();
        let bytes = kp.sk.to_bytes();

        assert_eq!(bytes[0], ED25519_SK_ID);

        let sk2 = SecretKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk2.sk.as_ref(), kp.sk.sk.as_ref());
    }

    #[test]
    fn test_secret_key_invalid_type() {
        let bytes = vec![0xFF, 1, 2, 3, 4]; // Invalid key type
        let result = SecretKey::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::UnsupportedKeyType));
    }

    #[test]
    fn test_secret_key_to_from_pem() {
        let kp = create_test_keypair();
        let pem = kp.sk.to_pem();

        assert!(pem.contains("PRIVATE KEY"));

        let sk2 = SecretKey::from_pem(&pem).unwrap();
        assert_eq!(sk2.sk.as_ref(), kp.sk.sk.as_ref());
    }

    #[test]
    fn test_secret_key_to_from_der() {
        let kp = create_test_keypair();
        let der = kp.sk.to_der();

        assert!(!der.is_empty());

        let sk2 = SecretKey::from_der(&der).unwrap();
        assert_eq!(sk2.sk.as_ref(), kp.sk.sk.as_ref());
    }

    #[test]
    fn test_secret_key_debug() {
        let kp = create_test_keypair();
        let debug_str = format!("{:?}", kp.sk);
        assert!(debug_str.contains("SecretKey"));
    }

    #[test]
    fn test_public_key_set_empty() {
        let set = PublicKeySet::empty();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_public_key_set_insert() {
        let mut set = PublicKeySet::empty();
        let kp = create_test_keypair();

        set.insert(kp.pk.clone()).unwrap();
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
    }

    #[test]
    fn test_public_key_set_insert_duplicate() {
        let mut set = PublicKeySet::empty();
        let kp = create_test_keypair();

        set.insert(kp.pk.clone()).unwrap();
        let result = set.insert(kp.pk.clone());

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::DuplicatePublicKey));
        assert_eq!(set.len(), 1); // Still only one key
    }

    #[test]
    fn test_public_key_set_remove() {
        let mut set = PublicKeySet::empty();
        let kp = create_test_keypair();

        set.insert(kp.pk.clone()).unwrap();
        assert_eq!(set.len(), 1);

        set.remove(&kp.pk).unwrap();
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_public_key_set_remove_unknown() {
        let mut set = PublicKeySet::empty();
        let kp = create_test_keypair();

        let result = set.remove(&kp.pk);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::UnknownPublicKey));
    }

    #[test]
    fn test_public_key_set_merge() {
        let mut set1 = PublicKeySet::empty();
        let mut set2 = PublicKeySet::empty();

        let kp1 = create_test_keypair();
        let kp2 = create_test_keypair();

        set1.insert(kp1.pk).unwrap();
        set2.insert(kp2.pk).unwrap();

        set1.merge(&set2).unwrap();
        assert_eq!(set1.len(), 2);
    }

    #[test]
    fn test_public_key_set_merge_duplicate() {
        let mut set1 = PublicKeySet::empty();
        let mut set2 = PublicKeySet::empty();

        let kp = create_test_keypair();

        set1.insert(kp.pk.clone()).unwrap();
        set2.insert(kp.pk.clone()).unwrap();

        let result = set1.merge(&set2);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_set_items() {
        let mut set = PublicKeySet::empty();
        let kp = create_test_keypair();
        set.insert(kp.pk.clone()).unwrap();

        let items = set.items();
        assert_eq!(items.len(), 1);
        assert!(items.contains(&kp.pk));
    }

    #[test]
    fn test_public_key_set_items_mut() {
        let mut set = PublicKeySet::empty();
        let kp = create_test_keypair();
        set.insert(kp.pk.clone()).unwrap();

        let items = set.items_mut();
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn test_public_key_set_attach_default_key_id() {
        let mut set = PublicKeySet::empty();
        let kp1 = create_test_keypair();
        let kp2 = create_test_keypair();

        set.insert(kp1.pk).unwrap();
        set.insert(kp2.pk).unwrap();

        let set_with_ids = set.attach_default_key_id();
        assert_eq!(set_with_ids.len(), 2);

        for pk in set_with_ids.items() {
            assert!(pk.key_id().is_some());
        }
    }

    #[test]
    fn test_public_key_set_new() {
        let kp = create_test_keypair();
        let mut hash_set = HashSet::new();
        hash_set.insert(kp.pk);

        let set = PublicKeySet::new(hash_set);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_keypair_clone_and_eq() {
        let kp1 = create_test_keypair();
        let kp2 = kp1.clone();
        assert_eq!(kp1, kp2);
    }

    #[test]
    fn test_public_key_clone_and_eq() {
        let kp = create_test_keypair();
        let pk1 = kp.pk.clone();
        let pk2 = kp.pk.clone();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_secret_key_clone_and_eq() {
        let kp = create_test_keypair();
        let sk1 = kp.sk.clone();
        let sk2 = kp.sk.clone();
        assert_eq!(sk1, sk2);
    }

    #[test]
    fn test_public_key_to_from_file() {
        let kp = create_test_keypair();
        let temp_file = std::env::temp_dir().join("test_pk.key");

        // Write to file
        kp.pk.to_file(&temp_file).unwrap();

        // Read from file
        let pk2 = PublicKey::from_file(&temp_file).unwrap();
        assert_eq!(pk2.pk.as_ref(), kp.pk.pk.as_ref());

        // Clean up
        std::fs::remove_file(temp_file).ok();
    }

    #[test]
    fn test_secret_key_to_from_file() {
        let kp = create_test_keypair();
        let temp_file = std::env::temp_dir().join("test_sk.key");

        // Write to file
        kp.sk.to_file(&temp_file).unwrap();

        // Read from file
        let sk2 = SecretKey::from_file(&temp_file).unwrap();
        assert_eq!(sk2.sk.as_ref(), kp.sk.sk.as_ref());

        // Clean up
        std::fs::remove_file(temp_file).ok();
    }

    #[test]
    fn test_public_key_hash() {
        let kp = create_test_keypair();
        let mut set = std::collections::HashSet::new();
        set.insert(kp.pk.clone());
        assert!(set.contains(&kp.pk));
    }

    #[test]
    fn test_secret_key_hash() {
        let kp = create_test_keypair();
        let mut set = std::collections::HashSet::new();
        set.insert(kp.sk.clone());
        assert!(set.contains(&kp.sk));
    }

    #[test]
    fn test_keypair_hash() {
        let kp1 = create_test_keypair();
        let mut set = std::collections::HashSet::new();
        set.insert(kp1.clone());
        assert!(set.contains(&kp1));
    }

    // ============================================================================
    // SECURITY TESTS: File Permission Enforcement (Issue #10)
    // ============================================================================

    #[cfg(unix)]
    #[test]
    fn test_secret_key_to_file_sets_secure_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let kp = create_test_keypair();
        let temp_file = std::env::temp_dir().join("test_sk_perms.key");

        // Write secret key
        kp.sk.to_file(&temp_file).unwrap();

        // Verify permissions are 0600 (owner read/write only)
        let metadata = std::fs::metadata(&temp_file).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "Secret key file should have mode 0600, got {:o}",
            mode
        );

        // Cleanup
        std::fs::remove_file(temp_file).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_secret_key_to_file_no_group_or_world_access() {
        use std::os::unix::fs::PermissionsExt;

        let kp = create_test_keypair();
        let temp_file = std::env::temp_dir().join("test_sk_no_world.key");

        // Write secret key
        kp.sk.to_file(&temp_file).unwrap();

        // Verify no group or world access
        let metadata = std::fs::metadata(&temp_file).unwrap();
        let mode = metadata.permissions().mode();

        // Check that group (0o070) and others (0o007) have no permissions
        assert_eq!(
            mode & 0o077,
            0,
            "Secret key file should not be accessible to group or others, mode: {:o}",
            mode & 0o777
        );

        // Cleanup
        std::fs::remove_file(temp_file).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_secret_key_overwrite_maintains_secure_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let kp1 = create_test_keypair();
        let kp2 = create_test_keypair();
        let temp_file = std::env::temp_dir().join("test_sk_overwrite.key");

        // Write first key
        kp1.sk.to_file(&temp_file).unwrap();

        // Verify initial permissions
        let mode1 = std::fs::metadata(&temp_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode1, 0o600);

        // Overwrite with second key
        kp2.sk.to_file(&temp_file).unwrap();

        // Verify permissions are still secure
        let mode2 = std::fs::metadata(&temp_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode2, 0o600,
            "Permissions should remain 0600 after overwrite"
        );

        // Verify content is new key
        let loaded = SecretKey::from_file(&temp_file).unwrap();
        assert_eq!(loaded.sk.as_ref(), kp2.sk.sk.as_ref());

        // Cleanup
        std::fs::remove_file(temp_file).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_secret_key_from_file_reads_insecure_file() {
        use std::os::unix::fs::PermissionsExt;

        let kp = create_test_keypair();
        let temp_file = std::env::temp_dir().join("test_sk_insecure_read.key");

        // Create file with insecure permissions manually
        std::fs::write(&temp_file, kp.sk.to_bytes()).unwrap();
        let mut perms = std::fs::metadata(&temp_file).unwrap().permissions();
        perms.set_mode(0o644); // world-readable
        std::fs::set_permissions(&temp_file, perms).unwrap();

        // Should still read successfully (but would log a warning)
        let loaded = SecretKey::from_file(&temp_file).unwrap();
        assert_eq!(loaded.sk.as_ref(), kp.sk.sk.as_ref());

        // Cleanup
        std::fs::remove_file(temp_file).ok();
    }
}
