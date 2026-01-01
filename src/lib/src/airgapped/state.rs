//! Device security state for anti-rollback protection

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Persistent device security state
///
/// This state must be stored in protected/secure storage on the device.
/// It tracks the current trust bundle version to prevent rollback attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSecurityState {
    /// Current trust bundle version (anti-rollback)
    ///
    /// Device must reject bundles with `version < bundle_version`.
    pub bundle_version: u32,

    /// Last successful verification timestamp
    ///
    /// Used for staleness detection. This is the `integrated_time`
    /// from the last verified signature.
    #[serde(default)]
    pub last_verification_time: Option<u64>,

    /// Build timestamp of verifier firmware
    ///
    /// Used as minimum epoch for signature timestamps.
    pub firmware_build_time: u64,

    /// Per-module version tracking (optional)
    ///
    /// Maps module identifier to version info for rollback detection.
    #[serde(default)]
    pub module_versions: BTreeMap<String, ModuleVersionInfo>,
}

impl DeviceSecurityState {
    /// Create initial state for a new device
    pub fn new(firmware_build_time: u64) -> Self {
        Self {
            bundle_version: 0,
            last_verification_time: None,
            firmware_build_time,
            module_versions: BTreeMap::new(),
        }
    }

    /// Create state with build timestamp from compile time
    pub fn with_build_timestamp() -> Self {
        Self::new(crate::time::BUILD_TIMESTAMP)
    }

    /// Check if a bundle version is acceptable
    pub fn check_bundle_version(&self, version: u32) -> bool {
        version >= self.bundle_version
    }

    /// Update bundle version after successful verification
    pub fn update_bundle_version(&mut self, version: u32) {
        if version > self.bundle_version {
            self.bundle_version = version;
        }
    }

    /// Update last verification time
    pub fn update_verification_time(&mut self, time: u64) {
        self.last_verification_time = Some(time);
    }

    /// Update module version tracking
    pub fn update_module_version(&mut self, module_id: &str, info: ModuleVersionInfo) {
        self.module_versions.insert(module_id.to_string(), info);
    }

    /// Check if a module version is acceptable (no downgrade)
    pub fn check_module_version(&self, module_id: &str, signature_time: u64) -> bool {
        if let Some(info) = self.module_versions.get(module_id) {
            // Signature must be at least as recent as the last seen
            signature_time >= info.signature_time
        } else {
            // First time seeing this module
            true
        }
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<Vec<u8>, crate::error::WSError> {
        serde_json::to_vec_pretty(self).map_err(|e| {
            crate::error::WSError::InternalError(format!("Failed to serialize state: {}", e))
        })
    }

    /// Deserialize from JSON
    pub fn from_json(data: &[u8]) -> Result<Self, crate::error::WSError> {
        serde_json::from_slice(data).map_err(|e| {
            crate::error::WSError::InternalError(format!("Failed to parse state: {}", e))
        })
    }
}

/// Module version tracking entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleVersionInfo {
    /// Semantic version string (if available)
    #[serde(default)]
    pub version: Option<String>,

    /// Signature timestamp (Rekor integrated_time)
    pub signature_time: u64,

    /// Module hash (SHA-256, hex-encoded)
    pub module_hash: String,
}

impl ModuleVersionInfo {
    /// Create new version info
    pub fn new(signature_time: u64, module_hash: &[u8]) -> Self {
        Self {
            version: None,
            signature_time,
            module_hash: hex::encode(module_hash),
        }
    }

    /// Create with semantic version
    pub fn with_version(mut self, version: &str) -> Self {
        self.version = Some(version.to_string());
        self
    }
}

/// Trait for secure storage backends
///
/// Implement this trait for your device's secure storage mechanism.
pub trait SecureStorage {
    /// Load device state from storage
    fn load_state(&self) -> Result<DeviceSecurityState, crate::error::WSError>;

    /// Save device state to storage
    fn save_state(&self, state: &DeviceSecurityState) -> Result<(), crate::error::WSError>;
}

/// In-memory storage for testing
#[derive(Debug, Default)]
pub struct MemoryStorage {
    state: std::sync::RwLock<Option<DeviceSecurityState>>,
}

impl MemoryStorage {
    /// Create new empty storage
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with initial state
    pub fn with_state(state: DeviceSecurityState) -> Self {
        Self {
            state: std::sync::RwLock::new(Some(state)),
        }
    }
}

impl SecureStorage for MemoryStorage {
    fn load_state(&self) -> Result<DeviceSecurityState, crate::error::WSError> {
        self.state
            .read()
            .map_err(|_| crate::error::WSError::InternalError("Lock poisoned".to_string()))?
            .clone()
            .ok_or_else(|| crate::error::WSError::InternalError("No state stored".to_string()))
    }

    fn save_state(&self, state: &DeviceSecurityState) -> Result<(), crate::error::WSError> {
        let mut guard = self
            .state
            .write()
            .map_err(|_| crate::error::WSError::InternalError("Lock poisoned".to_string()))?;
        *guard = Some(state.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_state_creation() {
        let state = DeviceSecurityState::new(1704067200);
        assert_eq!(state.bundle_version, 0);
        assert!(state.last_verification_time.is_none());
        assert_eq!(state.firmware_build_time, 1704067200);
    }

    #[test]
    fn test_bundle_version_check() {
        let mut state = DeviceSecurityState::new(1704067200);
        state.bundle_version = 5;

        assert!(state.check_bundle_version(5)); // Equal is OK
        assert!(state.check_bundle_version(6)); // Higher is OK
        assert!(!state.check_bundle_version(4)); // Lower is rejected
    }

    #[test]
    fn test_bundle_version_update() {
        let mut state = DeviceSecurityState::new(1704067200);

        state.update_bundle_version(5);
        assert_eq!(state.bundle_version, 5);

        state.update_bundle_version(3); // Lower version ignored
        assert_eq!(state.bundle_version, 5);

        state.update_bundle_version(7);
        assert_eq!(state.bundle_version, 7);
    }

    #[test]
    fn test_module_version_tracking() {
        let mut state = DeviceSecurityState::new(1704067200);

        // First time seeing module
        assert!(state.check_module_version("my-module", 1000));

        // Update with version info
        state.update_module_version(
            "my-module",
            ModuleVersionInfo::new(1000, &[0u8; 32]),
        );

        // Same or newer is OK
        assert!(state.check_module_version("my-module", 1000));
        assert!(state.check_module_version("my-module", 2000));

        // Older is rejected
        assert!(!state.check_module_version("my-module", 500));
    }

    #[test]
    fn test_state_json_roundtrip() {
        let mut state = DeviceSecurityState::new(1704067200);
        state.bundle_version = 42;
        state.update_verification_time(1704100000);

        let json = state.to_json().unwrap();
        let parsed = DeviceSecurityState::from_json(&json).unwrap();

        assert_eq!(parsed.bundle_version, 42);
        assert_eq!(parsed.last_verification_time, Some(1704100000));
    }

    #[test]
    fn test_memory_storage() {
        let storage = MemoryStorage::new();

        // Initially empty
        assert!(storage.load_state().is_err());

        // Save and load
        let state = DeviceSecurityState::new(1704067200);
        storage.save_state(&state).unwrap();

        let loaded = storage.load_state().unwrap();
        assert_eq!(loaded.firmware_build_time, 1704067200);
    }
}
