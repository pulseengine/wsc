pub use crate::error::*;

use ct_codecs::{Encoder, Hex};
use ssh_keys::{self, openssh};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, prelude::*};
use std::path::Path;
use std::{fmt, str};

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

    /// Parse a single OpenSSH public key.
    pub fn from_openssh(lines: &str) -> Result<Self, WSError> {
        for line in lines.lines() {
            let line = line.trim();
            if let Ok(ssh_keys::PublicKey::Ed25519(raw)) = openssh::parse_public_key(line) {
                let mut bytes = vec![ED25519_PK_ID];
                bytes.extend_from_slice(&raw);
                if let Ok(pk) = PublicKey::from_bytes(&bytes) {
                    return Ok(pk);
                }
            };
        }
        Err(WSError::ParseError)
    }

    /// Parse a single OpenSSH public key from a file.
    pub fn from_openssh_file(file: impl AsRef<Path>) -> Result<Self, WSError> {
        let mut fp = File::open(file)?;
        let mut lines = String::new();
        fp.read_to_string(&mut lines)?;
        Self::from_openssh(&lines)
    }

    /// Try to guess the public key format.
    pub fn from_any(data: &[u8]) -> Result<Self, WSError> {
        if let Ok(pk) = Self::from_bytes(data) {
            return Ok(pk);
        }
        if let Ok(pk) = Self::from_der(data) {
            return Ok(pk);
        }
        let s = str::from_utf8(data).map_err(|_| WSError::ParseError)?;
        if let Ok(pk) = Self::from_pem(s) {
            return Ok(pk);
        }
        if let Ok(pk) = Self::from_openssh(s) {
            return Ok(pk);
        }
        Err(WSError::ParseError)
    }

    /// Load a key from a file, trying to guess its format.
    pub fn from_any_file(file: impl AsRef<Path>) -> Result<Self, WSError> {
        let mut fp = File::open(file)?;
        let mut bytes = vec![];
        fp.read_to_end(&mut bytes)?;
        Self::from_any(&bytes)
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
            Hex::encode_to_string(self.pk.as_ref()).unwrap(),
            self.key_id()
                .map(|key_id| format!("[{}]", Hex::encode_to_string(key_id).unwrap()))
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
    pub fn from_file(file: impl AsRef<Path>) -> Result<Self, WSError> {
        let mut fp = File::open(file)?;
        let mut bytes = vec![];
        fp.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    /// Save a secret key to a file.
    pub fn to_file(&self, file: impl AsRef<Path>) -> Result<(), WSError> {
        let mut fp = File::create(file)?;
        fp.write_all(&self.to_bytes())?;
        Ok(())
    }

    /// Parse an OpenSSH secret key.
    pub fn from_openssh(lines: &str) -> Result<Self, WSError> {
        for sk in openssh::parse_private_key(lines).map_err(|_| WSError::ParseError)? {
            if let ssh_keys::PrivateKey::Ed25519(raw) = sk {
                let mut bytes = vec![ED25519_SK_ID];
                bytes.extend_from_slice(&raw);
                return Self::from_bytes(&bytes);
            }
        }
        Err(WSError::UnsupportedKeyType)
    }

    /// Read an OpenSSH key from a file.
    pub fn from_openssh_file(file: impl AsRef<Path>) -> Result<Self, WSError> {
        let mut fp = File::open(file)?;
        let mut lines = String::new();
        fp.read_to_string(&mut lines)?;
        Self::from_openssh(&lines)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SecretKey {{ [{}] }}",
            Hex::encode_to_string(self.sk.as_ref()).unwrap(),
        )
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

    /// Parse an OpenSSH public key set.
    pub fn from_openssh(lines: &str) -> Result<Self, WSError> {
        let mut pks = PublicKeySet::empty();
        for line in lines.lines() {
            let line = line.trim();
            if let Ok(ssh_keys::PublicKey::Ed25519(raw)) = openssh::parse_public_key(line) {
                let mut bytes = vec![ED25519_PK_ID];
                bytes.extend_from_slice(&raw);
                if let Ok(pk) = PublicKey::from_bytes(&bytes) {
                    pks.pks.insert(pk);
                }
            };
        }
        Ok(pks)
    }

    /// Parse an OpenSSH public key set from a file.
    pub fn from_openssh_file(file: impl AsRef<Path>) -> Result<Self, WSError> {
        let mut fp = File::open(file)?;
        let mut lines = String::new();
        fp.read_to_string(&mut lines)?;
        Self::from_openssh(&lines)
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

    /// Parse and add a key to the set, trying to guess its format.
    pub fn insert_any(&mut self, data: &[u8]) -> Result<(), WSError> {
        if let Ok(s) = str::from_utf8(data)
            && let Ok(pk) = PublicKey::from_openssh(s)
        {
            self.insert(pk)?;
            return Ok(());
        }
        let pk = PublicKey::from_any(data)?;
        self.insert(pk)
    }

    /// Load, parse and add a key to the set, trying to guess its format.
    pub fn insert_any_file(&mut self, file: impl AsRef<Path>) -> Result<(), WSError> {
        let mut fp = File::open(file)?;
        let mut data = vec![];
        fp.read_to_end(&mut data)?;
        self.insert_any(&data)
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
    fn test_public_key_from_any_bytes() {
        let kp = create_test_keypair();
        let bytes = kp.pk.to_bytes();
        let pk = PublicKey::from_any(&bytes).unwrap();
        assert_eq!(pk.pk.as_ref(), kp.pk.pk.as_ref());
    }

    #[test]
    fn test_public_key_from_any_der() {
        let kp = create_test_keypair();
        let der = kp.pk.to_der();
        let pk = PublicKey::from_any(&der).unwrap();
        assert_eq!(pk.pk.as_ref(), kp.pk.pk.as_ref());
    }

    #[test]
    fn test_public_key_from_any_pem() {
        let kp = create_test_keypair();
        let pem = kp.pk.to_pem();
        let pk = PublicKey::from_any(pem.as_bytes()).unwrap();
        assert_eq!(pk.pk.as_ref(), kp.pk.pk.as_ref());
    }

    #[test]
    fn test_public_key_from_any_invalid() {
        let invalid_data = b"not a valid key";
        let result = PublicKey::from_any(invalid_data);
        assert!(result.is_err());
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
    fn test_public_key_set_insert_any() {
        let mut set = PublicKeySet::empty();
        let kp = create_test_keypair();
        let bytes = kp.pk.to_bytes();

        set.insert_any(&bytes).unwrap();
        assert_eq!(set.len(), 1);
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
    fn test_public_key_from_any_file() {
        let kp = create_test_keypair();
        let temp_file = std::env::temp_dir().join("test_pk_any.key");

        // Write PEM format
        std::fs::write(&temp_file, kp.pk.to_pem()).unwrap();

        // Read with from_any_file
        let pk2 = PublicKey::from_any_file(&temp_file).unwrap();
        assert_eq!(pk2.pk.as_ref(), kp.pk.pk.as_ref());

        // Clean up
        std::fs::remove_file(temp_file).ok();
    }

    #[test]
    fn test_public_key_set_from_openssh() {
        // Just test that it can parse an empty string without crashing
        let result = PublicKeySet::from_openssh("");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_public_key_from_openssh_invalid() {
        let result = PublicKey::from_openssh("invalid ssh key data");
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_set_insert_any_invalid() {
        let mut set = PublicKeySet::empty();
        let result = set.insert_any(b"invalid key data");
        assert!(result.is_err());
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

    #[test]
    fn test_public_key_set_from_openssh_file_missing() {
        let temp_file = std::env::temp_dir().join("nonexistent_openssh.key");
        let result = PublicKeySet::from_openssh_file(&temp_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_from_openssh_file_missing() {
        let temp_file = std::env::temp_dir().join("nonexistent_pk.key");
        let result = PublicKey::from_openssh_file(&temp_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_key_from_openssh_invalid() {
        let result = SecretKey::from_openssh("invalid data");
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_set_insert_any_file_missing() {
        let mut set = PublicKeySet::empty();
        let temp_file = std::env::temp_dir().join("nonexistent_any.key");
        let result = set.insert_any_file(&temp_file);
        assert!(result.is_err());
    }
}
