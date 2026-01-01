//! Storage abstraction for trust bundles and verifier keys
//!
//! Provides traits for accessing trust material from various storage backends:
//! - HSM (Hardware Security Module)
//! - TPM (Trusted Platform Module)
//! - Secure Element (e.g., ATECC608)
//! - Flash with encryption
//! - Compiled into firmware
//! - File system (development)
//!
//! # Design Philosophy
//!
//! Similar to [`TimeSource`](crate::time::TimeSource), these traits abstract
//! hardware-specific storage access so the same verification code works across:
//! - Development machines (file-based)
//! - Production devices (HSM/TPM)
//! - Constrained embedded (compiled-in)
//!
//! # Example
//!
//! ```rust,ignore
//! use wsc::airgapped::{TrustStore, KeyStore, AirGappedVerifier};
//!
//! // For embedded: keys compiled into firmware
//! struct FirmwareStore;
//! impl KeyStore for FirmwareStore {
//!     fn load_verifier_key(&self) -> Result<Vec<u8>, WSError> {
//!         Ok(include_bytes!("verifier.pub").to_vec())
//!     }
//! }
//!
//! // For HSM: delegate to hardware
//! struct HsmStore { slot: u32 }
//! impl KeyStore for HsmStore {
//!     fn load_verifier_key(&self) -> Result<Vec<u8>, WSError> {
//!         hsm_read_public_key(self.slot)
//!     }
//! }
//! ```

use crate::airgapped::SignedTrustBundle;
use crate::error::WSError;

/// Trait for loading trust bundles from storage
///
/// Implement this trait for your device's storage mechanism:
/// - Flash memory
/// - Secure storage partition
/// - Network fetch (for semi-connected devices)
/// - Compiled-in bundles
pub trait TrustStore: Send + Sync {
    /// Load the signed trust bundle from storage
    ///
    /// Returns the signed bundle which can then be verified
    /// using the verifier key from [`KeyStore`].
    fn load_bundle(&self) -> Result<SignedTrustBundle, WSError>;

    /// Save a new trust bundle to storage (optional)
    ///
    /// Not all implementations support saving (e.g., compiled-in bundles).
    /// Returns `Err` if saving is not supported or fails.
    fn save_bundle(&self, bundle: &SignedTrustBundle) -> Result<(), WSError> {
        let _ = bundle;
        Err(WSError::InternalError("Bundle saving not supported".to_string()))
    }

    /// Check if storage is available and accessible
    fn is_available(&self) -> bool {
        true
    }

    /// Get storage metadata (for diagnostics)
    fn metadata(&self) -> StorageMetadata {
        StorageMetadata::default()
    }
}

/// Trait for loading verifier keys from secure storage
///
/// The verifier key is the public key used to verify trust bundle signatures.
/// It should be stored in the most secure location available:
/// - OTP (One-Time Programmable) fuses
/// - TPM/HSM
/// - Secure Element
/// - Protected flash region
///
/// # Security
///
/// The verifier key is the root of trust for the entire verification chain.
/// Compromise of this key allows an attacker to provision malicious bundles.
pub trait KeyStore: Send + Sync {
    /// Load the bundle verifier public key (Ed25519, 32 bytes)
    ///
    /// This key verifies the signature on trust bundles.
    fn load_verifier_key(&self) -> Result<Vec<u8>, WSError>;

    /// Check if the key is hardware-protected
    ///
    /// Returns true if the key is stored in HSM, TPM, or secure element.
    fn is_hardware_backed(&self) -> bool {
        false
    }

    /// Get key metadata (for diagnostics)
    fn key_metadata(&self) -> KeyMetadata {
        KeyMetadata::default()
    }
}

/// Metadata about storage backend
#[derive(Debug, Clone, Default)]
pub struct StorageMetadata {
    /// Human-readable storage type
    pub storage_type: &'static str,

    /// Whether storage is read-only
    pub read_only: bool,

    /// Whether storage is encrypted
    pub encrypted: bool,

    /// Whether storage is hardware-protected
    pub hardware_protected: bool,
}

/// Metadata about key storage
#[derive(Debug, Clone, Default)]
pub struct KeyMetadata {
    /// Key identifier (for multi-key scenarios)
    pub key_id: Option<String>,

    /// Whether key is in hardware (HSM/TPM/SE)
    pub hardware_backed: bool,

    /// Whether key can be extracted
    pub extractable: bool,

    /// Key algorithm
    pub algorithm: &'static str,
}

// ============================================================================
// Built-in implementations
// ============================================================================

/// In-memory trust store for testing
#[derive(Debug, Clone)]
pub struct MemoryTrustStore {
    bundle: Option<SignedTrustBundle>,
}

impl MemoryTrustStore {
    /// Create empty store
    pub fn new() -> Self {
        Self { bundle: None }
    }

    /// Create with pre-loaded bundle
    pub fn with_bundle(bundle: SignedTrustBundle) -> Self {
        Self { bundle: Some(bundle) }
    }
}

impl Default for MemoryTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustStore for MemoryTrustStore {
    fn load_bundle(&self) -> Result<SignedTrustBundle, WSError> {
        self.bundle
            .clone()
            .ok_or_else(|| WSError::InternalError("No bundle in memory store".to_string()))
    }

    fn save_bundle(&self, _bundle: &SignedTrustBundle) -> Result<(), WSError> {
        // Can't mutate through shared reference; use interior mutability if needed
        Err(WSError::InternalError("MemoryTrustStore is immutable".to_string()))
    }

    fn metadata(&self) -> StorageMetadata {
        StorageMetadata {
            storage_type: "memory",
            read_only: true,
            encrypted: false,
            hardware_protected: false,
        }
    }
}

/// In-memory key store for testing
#[derive(Debug, Clone)]
pub struct MemoryKeyStore {
    verifier_key: Vec<u8>,
}

impl MemoryKeyStore {
    /// Create with verifier key
    pub fn new(verifier_key: Vec<u8>) -> Self {
        Self { verifier_key }
    }
}

impl KeyStore for MemoryKeyStore {
    fn load_verifier_key(&self) -> Result<Vec<u8>, WSError> {
        Ok(self.verifier_key.clone())
    }

    fn key_metadata(&self) -> KeyMetadata {
        KeyMetadata {
            key_id: None,
            hardware_backed: false,
            extractable: true,
            algorithm: "Ed25519",
        }
    }
}

/// File-based trust store for development
#[cfg(not(target_os = "wasi"))]
#[derive(Debug, Clone)]
pub struct FileTrustStore {
    path: std::path::PathBuf,
}

#[cfg(not(target_os = "wasi"))]
impl FileTrustStore {
    /// Create store pointing to a file path
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[cfg(not(target_os = "wasi"))]
impl TrustStore for FileTrustStore {
    fn load_bundle(&self) -> Result<SignedTrustBundle, WSError> {
        let data = std::fs::read(&self.path).map_err(|e| {
            WSError::InternalError(format!("Failed to read bundle file: {}", e))
        })?;
        SignedTrustBundle::from_json(&data)
    }

    fn save_bundle(&self, bundle: &SignedTrustBundle) -> Result<(), WSError> {
        let data = bundle.to_json()?;
        std::fs::write(&self.path, data).map_err(|e| {
            WSError::InternalError(format!("Failed to write bundle file: {}", e))
        })
    }

    fn metadata(&self) -> StorageMetadata {
        StorageMetadata {
            storage_type: "file",
            read_only: false,
            encrypted: false,
            hardware_protected: false,
        }
    }
}

/// File-based key store for development
#[cfg(not(target_os = "wasi"))]
#[derive(Debug, Clone)]
pub struct FileKeyStore {
    path: std::path::PathBuf,
}

#[cfg(not(target_os = "wasi"))]
impl FileKeyStore {
    /// Create store pointing to a public key file
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[cfg(not(target_os = "wasi"))]
impl KeyStore for FileKeyStore {
    fn load_verifier_key(&self) -> Result<Vec<u8>, WSError> {
        let data = std::fs::read(&self.path).map_err(|e| {
            WSError::InternalError(format!("Failed to read key file: {}", e))
        })?;

        // Handle wsc key format (1-byte prefix + 32-byte key)
        if data.len() == 33 {
            Ok(data[1..].to_vec())
        } else if data.len() == 32 {
            Ok(data)
        } else {
            Err(WSError::InternalError(format!(
                "Invalid key file size: {} (expected 32 or 33)",
                data.len()
            )))
        }
    }

    fn key_metadata(&self) -> KeyMetadata {
        KeyMetadata {
            key_id: None,
            hardware_backed: false,
            extractable: true,
            algorithm: "Ed25519",
        }
    }
}

/// Compiled-in bundle store for embedded devices
///
/// Use this when the bundle is compiled into firmware.
///
/// # Example
///
/// ```rust,ignore
/// static BUNDLE_DATA: &[u8] = include_bytes!("trust-bundle.json");
/// let store = CompiledTrustStore::new(BUNDLE_DATA);
/// ```
#[derive(Debug, Clone)]
pub struct CompiledTrustStore {
    data: &'static [u8],
}

impl CompiledTrustStore {
    /// Create from static byte slice
    pub const fn new(data: &'static [u8]) -> Self {
        Self { data }
    }
}

impl TrustStore for CompiledTrustStore {
    fn load_bundle(&self) -> Result<SignedTrustBundle, WSError> {
        SignedTrustBundle::from_json(self.data)
    }

    fn metadata(&self) -> StorageMetadata {
        StorageMetadata {
            storage_type: "compiled",
            read_only: true,
            encrypted: false,
            hardware_protected: false,
        }
    }
}

/// Compiled-in key store for embedded devices
///
/// Use this when the verifier key is compiled into firmware.
#[derive(Debug, Clone)]
pub struct CompiledKeyStore {
    key: &'static [u8],
}

impl CompiledKeyStore {
    /// Create from static byte slice (32 bytes for Ed25519)
    pub const fn new(key: &'static [u8]) -> Self {
        Self { key }
    }
}

impl KeyStore for CompiledKeyStore {
    fn load_verifier_key(&self) -> Result<Vec<u8>, WSError> {
        if self.key.len() == 32 {
            Ok(self.key.to_vec())
        } else if self.key.len() == 33 {
            // Handle wsc format with prefix
            Ok(self.key[1..].to_vec())
        } else {
            Err(WSError::InternalError(format!(
                "Invalid compiled key size: {}",
                self.key.len()
            )))
        }
    }

    fn key_metadata(&self) -> KeyMetadata {
        KeyMetadata {
            key_id: None,
            hardware_backed: false,
            extractable: false, // Can't extract from binary easily
            algorithm: "Ed25519",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airgapped::TrustBundle;

    fn create_test_bundle() -> SignedTrustBundle {
        use ed25519_compact::KeyPair;

        let keypair = KeyPair::generate();
        let bundle = TrustBundle::new(1, 365);
        let seed = keypair.sk.seed();
        SignedTrustBundle::sign(bundle, seed.as_ref()).unwrap()
    }

    #[test]
    fn test_memory_trust_store() {
        let bundle = create_test_bundle();
        let store = MemoryTrustStore::with_bundle(bundle.clone());

        let loaded = store.load_bundle().unwrap();
        assert_eq!(loaded.bundle.version, bundle.bundle.version);
    }

    #[test]
    fn test_memory_trust_store_empty() {
        let store = MemoryTrustStore::new();
        assert!(store.load_bundle().is_err());
    }

    #[test]
    fn test_memory_key_store() {
        let key = vec![0u8; 32];
        let store = MemoryKeyStore::new(key.clone());

        let loaded = store.load_verifier_key().unwrap();
        assert_eq!(loaded, key);
    }

    #[test]
    fn test_compiled_key_store() {
        static KEY: &[u8] = &[1u8; 32];
        let store = CompiledKeyStore::new(KEY);

        let loaded = store.load_verifier_key().unwrap();
        assert_eq!(loaded.len(), 32);
    }

    #[test]
    fn test_storage_metadata() {
        let store = MemoryTrustStore::new();
        let meta = store.metadata();
        assert_eq!(meta.storage_type, "memory");
        assert!(!meta.hardware_protected);
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn test_file_trust_store() {
        let bundle = create_test_bundle();
        let path = std::env::temp_dir().join("test-bundle-storage.json");

        // Save and load
        std::fs::write(&path, bundle.to_json().unwrap()).unwrap();

        let store = FileTrustStore::new(&path);
        let loaded = store.load_bundle().unwrap();
        assert_eq!(loaded.bundle.version, bundle.bundle.version);

        std::fs::remove_file(&path).ok();
    }
}
