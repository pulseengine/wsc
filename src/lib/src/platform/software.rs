/// Software-based key provider (development/testing only)
///
/// This implementation stores keys in process memory without hardware protection.
///
/// # Security Warning
///
/// **NOT SUITABLE FOR PRODUCTION USE**
///
/// - Keys stored in process memory
/// - No hardware protection
/// - Vulnerable to memory dumps, debuggers, core files
/// - No physical security
///
/// Use only for:
/// - Development and testing
/// - CI/CD pipelines (ephemeral keys)
/// - Scenarios where key security is not required

use super::{Attestation, KeyHandle, SecureKeyProvider, SecurityLevel};
use crate::error::WSError;
use crate::signature::{KeyPair, PublicKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Software-based key storage
///
/// Keys are stored in an in-memory HashMap with simple integer handles.
struct KeyStore {
    next_handle: u64,
    keys: HashMap<u64, KeyPair>,
}

impl KeyStore {
    fn new() -> Self {
        KeyStore {
            next_handle: 1,
            keys: HashMap::new(),
        }
    }

    fn insert(&mut self, keypair: KeyPair) -> KeyHandle {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.keys.insert(handle, keypair);
        KeyHandle::from_raw(handle)
    }

    fn get(&self, handle: KeyHandle) -> Option<&KeyPair> {
        self.keys.get(&handle.as_raw())
    }

    fn remove(&mut self, handle: KeyHandle) -> Option<KeyPair> {
        self.keys.remove(&handle.as_raw())
    }

    fn list(&self) -> Vec<KeyHandle> {
        self.keys.keys().map(|&h| KeyHandle::from_raw(h)).collect()
    }
}

/// Software key provider implementation
///
/// # Example
///
/// ```ignore
/// use wsc::platform::software::SoftwareProvider;
/// use wsc::platform::SecureKeyProvider;
///
/// let provider = SoftwareProvider::new();
///
/// // Generate key
/// let handle = provider.generate_key()?;
///
/// // Sign data
/// let signature = provider.sign(handle, b"test data")?;
///
/// // Get public key
/// let public_key = provider.get_public_key(handle)?;
/// ```
pub struct SoftwareProvider {
    store: Arc<Mutex<KeyStore>>,
}

impl SoftwareProvider {
    /// Create a new software key provider
    pub fn new() -> Self {
        log::warn!(
            "Creating software key provider - NOT SUITABLE FOR PRODUCTION. \
             Keys are stored in process memory without hardware protection."
        );

        SoftwareProvider {
            store: Arc::new(Mutex::new(KeyStore::new())),
        }
    }

    /// Import an existing key pair
    ///
    /// This is useful for migrating existing software keys to the new
    /// platform abstraction without regenerating.
    ///
    /// # Arguments
    ///
    /// * `keypair` - The key pair to import
    ///
    /// # Returns
    ///
    /// A handle to the imported key
    pub fn import_keypair(&self, keypair: KeyPair) -> Result<KeyHandle, WSError> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| WSError::InternalError(format!("Lock poisoned: {}", e)))?;

        Ok(store.insert(keypair))
    }

    /// Export a key pair
    ///
    /// # Security Warning
    ///
    /// This exposes the private key! Only use for testing or migration.
    ///
    /// # Arguments
    ///
    /// * `handle` - Handle to the key to export
    ///
    /// # Returns
    ///
    /// The key pair (including private key)
    pub fn export_keypair(&self, handle: KeyHandle) -> Result<KeyPair, WSError> {
        let store = self
            .store
            .lock()
            .map_err(|e| WSError::InternalError(format!("Lock poisoned: {}", e)))?;

        store
            .get(handle)
            .cloned()
            .ok_or_else(|| WSError::InternalError("Invalid key handle".to_string()))
    }
}

impl Default for SoftwareProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureKeyProvider for SoftwareProvider {
    fn name(&self) -> &str {
        "Software (Development Only)"
    }

    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::Software
    }

    fn health_check(&self) -> Result<(), WSError> {
        // Software provider is always healthy
        Ok(())
    }

    fn generate_key(&self) -> Result<KeyHandle, WSError> {
        let keypair = KeyPair::generate();

        let mut store = self
            .store
            .lock()
            .map_err(|e| WSError::InternalError(format!("Lock poisoned: {}", e)))?;

        Ok(store.insert(keypair))
    }

    fn load_key(&self, _key_id: &str) -> Result<KeyHandle, WSError> {
        // Software provider doesn't support persistent key IDs
        // This would require serialization to disk, which defeats the purpose
        // of being a simple in-memory provider
        Err(WSError::UsageError(
            "Software provider does not support loading keys by ID. \
             Use import_keypair() instead for testing purposes.",
        ))
    }

    fn sign(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, WSError> {
        let store = self
            .store
            .lock()
            .map_err(|e| WSError::InternalError(format!("Lock poisoned: {}", e)))?;

        let keypair = store
            .get(handle)
            .ok_or_else(|| WSError::InternalError("Invalid key handle".to_string()))?;

        // Use existing signing implementation
        let signature = keypair.sk.sk.sign(data, None);

        Ok(signature.to_vec())
    }

    fn get_public_key(&self, handle: KeyHandle) -> Result<PublicKey, WSError> {
        let store = self
            .store
            .lock()
            .map_err(|e| WSError::InternalError(format!("Lock poisoned: {}", e)))?;

        let keypair = store
            .get(handle)
            .ok_or_else(|| WSError::InternalError("Invalid key handle".to_string()))?;

        Ok(keypair.pk.clone())
    }

    fn attestation(&self, _handle: KeyHandle) -> Result<Option<Attestation>, WSError> {
        // Software keys cannot be attested
        Ok(None)
    }

    fn delete_key(&self, handle: KeyHandle) -> Result<(), WSError> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| WSError::InternalError(format!("Lock poisoned: {}", e)))?;

        store
            .remove(handle)
            .ok_or_else(|| WSError::InternalError("Invalid key handle".to_string()))?;

        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<KeyHandle>, WSError> {
        let store = self
            .store
            .lock()
            .map_err(|e| WSError::InternalError(format!("Lock poisoned: {}", e)))?;

        Ok(store.list())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_provider_creation() {
        let provider = SoftwareProvider::new();
        assert_eq!(provider.name(), "Software (Development Only)");
        assert_eq!(provider.security_level(), SecurityLevel::Software);
    }

    #[test]
    fn test_health_check() {
        let provider = SoftwareProvider::new();
        assert!(provider.health_check().is_ok());
    }

    #[test]
    fn test_generate_key() {
        let provider = SoftwareProvider::new();
        let result = provider.generate_key();
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_and_verify() {
        let provider = SoftwareProvider::new();

        // Generate key
        let handle = provider.generate_key().expect("Failed to generate key");

        // Sign data
        let data = b"test data to sign";
        let signature = provider.sign(handle, data).expect("Failed to sign");

        // Get public key
        let public_key = provider
            .get_public_key(handle)
            .expect("Failed to get public key");

        // Verify signature using ed25519-compact
        let sig = ed25519_compact::Signature::from_slice(&signature).expect("Invalid signature");
        let result = public_key.pk.verify(data, &sig);
        assert!(result.is_ok(), "Signature verification failed");
    }

    #[test]
    fn test_multiple_keys() {
        let provider = SoftwareProvider::new();

        // Generate multiple keys
        let handle1 = provider.generate_key().expect("Failed to generate key 1");
        let handle2 = provider.generate_key().expect("Failed to generate key 2");

        // Ensure they're different
        assert_ne!(handle1, handle2);

        // List keys
        let keys = provider.list_keys().expect("Failed to list keys");
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&handle1));
        assert!(keys.contains(&handle2));
    }

    #[test]
    fn test_delete_key() {
        let provider = SoftwareProvider::new();

        // Generate key
        let handle = provider.generate_key().expect("Failed to generate key");

        // Verify it exists
        let keys = provider.list_keys().expect("Failed to list keys");
        assert_eq!(keys.len(), 1);

        // Delete key
        provider.delete_key(handle).expect("Failed to delete key");

        // Verify it's gone
        let keys = provider.list_keys().expect("Failed to list keys");
        assert_eq!(keys.len(), 0);

        // Try to use deleted key (should fail)
        let result = provider.sign(handle, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_handle() {
        let provider = SoftwareProvider::new();

        // Try to use non-existent handle
        let invalid_handle = KeyHandle::from_raw(9999);
        let result = provider.sign(invalid_handle, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_attestation_not_supported() {
        let provider = SoftwareProvider::new();
        let handle = provider.generate_key().expect("Failed to generate key");

        let attestation = provider
            .attestation(handle)
            .expect("Attestation check failed");
        assert!(attestation.is_none(), "Software keys should not support attestation");
    }

    #[test]
    fn test_load_key_not_supported() {
        let provider = SoftwareProvider::new();

        // load_key is not supported for software provider
        let result = provider.load_key("some-key-id");
        assert!(result.is_err());
    }

    #[test]
    fn test_import_export_keypair() {
        let provider = SoftwareProvider::new();

        // Generate a key pair the old way
        let original_keypair = KeyPair::generate();

        // Import it
        let handle = provider
            .import_keypair(original_keypair.clone())
            .expect("Failed to import keypair");

        // Export it
        let exported_keypair = provider
            .export_keypair(handle)
            .expect("Failed to export keypair");

        // Verify they match
        assert_eq!(original_keypair.pk.pk, exported_keypair.pk.pk);
        assert_eq!(original_keypair.sk.sk, exported_keypair.sk.sk);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let provider = Arc::new(SoftwareProvider::new());
        let mut handles = vec![];

        // Spawn multiple threads that generate keys
        for _ in 0..10 {
            let provider_clone = Arc::clone(&provider);
            let handle = thread::spawn(move || provider_clone.generate_key());
            handles.push(handle);
        }

        // Wait for all threads
        let mut key_handles = vec![];
        for handle in handles {
            let result = handle.join().expect("Thread panicked");
            key_handles.push(result.expect("Failed to generate key"));
        }

        // Verify all keys are unique
        let mut seen = std::collections::HashSet::new();
        for handle in &key_handles {
            assert!(seen.insert(handle.as_raw()), "Duplicate key handle");
        }

        // Verify we can list all keys
        let keys = provider.list_keys().expect("Failed to list keys");
        assert_eq!(keys.len(), 10);
    }
}
