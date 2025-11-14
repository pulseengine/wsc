/// Platform-specific hardware security integration
///
/// This module provides a unified interface for hardware-backed cryptographic operations
/// across different platforms and security modules.
///
/// # Supported Platforms
///
/// - **Software** (development/testing): In-memory keys, software crypto
/// - **TPM 2.0** (production): Linux/Windows TPM integration
/// - **Secure Elements** (IoT/embedded): ATECC608, SE050, etc.
/// - **TrustZone** (ARM): OP-TEE integration
/// - **SGX** (Intel): Enclave-based key operations
///
/// # Architecture
///
/// ```text
/// ┌─────────────────────┐
/// │   Application       │
/// │   (wsc signing)     │
/// └──────────┬──────────┘
///            │
///            ▼
/// ┌─────────────────────┐
/// │ SecureKeyProvider   │  ◄─── Trait (this file)
/// │     (trait)         │
/// └──────────┬──────────┘
///            │
///      ┌─────┴─────┬─────────┬──────────┐
///      ▼           ▼         ▼          ▼
///   Software    TPM 2.0   Secure     TrustZone
///   Provider    Provider  Element    Provider
/// ```
///
/// # Security Principles
///
/// 1. **Keys never exposed**: Private keys never leave hardware
/// 2. **Minimal trust**: Reduce trusted computing base
/// 3. **Defense in depth**: Multiple security layers
/// 4. **Fail secure**: Errors never expose key material

use crate::error::WSError;
use crate::signature::PublicKey;
use std::fmt;

#[cfg(feature = "software-keys")]
pub mod software;

#[cfg(feature = "tpm2")]
pub mod tpm2;

#[cfg(feature = "secure-element")]
pub mod secure_element;

#[cfg(feature = "trustzone")]
pub mod trustzone;

#[cfg(feature = "sgx")]
pub mod sgx;

/// Handle to a hardware-backed cryptographic key
///
/// This is an opaque reference to a key stored in secure hardware.
/// The actual key material is never exposed to the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHandle(u64);

impl KeyHandle {
    /// Create a new key handle from a raw value
    ///
    /// # Security
    ///
    /// This should only be called by platform-specific implementations
    /// with values obtained from the secure hardware.
    pub fn from_raw(value: u64) -> Self {
        KeyHandle(value)
    }

    /// Get the raw handle value
    ///
    /// # Security
    ///
    /// This is only for passing to platform-specific APIs.
    /// The value has no meaning outside the specific hardware context.
    pub fn as_raw(&self) -> u64 {
        self.0
    }
}

/// Attestation data proving key provenance
///
/// This contains cryptographic proof that a key was generated in
/// and is protected by specific hardware.
#[derive(Debug, Clone)]
pub struct Attestation {
    /// Type of attestation (TPM quote, SGX report, etc.)
    pub attestation_type: AttestationType,
    /// Attestation data (platform-specific format)
    pub data: Vec<u8>,
    /// Signature over attestation (if applicable)
    pub signature: Option<Vec<u8>>,
}

/// Type of hardware attestation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationType {
    /// No attestation available
    None,
    /// TPM 2.0 Quote (includes PCR values)
    Tpm2Quote,
    /// Intel SGX Remote Attestation Report
    SgxReport,
    /// ARM TrustZone Attestation
    TrustZoneAttestation,
    /// Secure Element Certificate
    SecureElementCert,
}

/// Unified interface for hardware-backed cryptographic key operations
///
/// This trait abstracts over different hardware security modules,
/// providing a consistent API regardless of the underlying platform.
///
/// # Security Guarantees
///
/// Implementations MUST ensure:
/// 1. Private keys never leave hardware
/// 2. All operations are performed within secure boundary
/// 3. Key handles are validated before use
/// 4. Errors never leak key material
///
/// # Example
///
/// ```ignore
/// use wsc::platform::{SecureKeyProvider, detect_platform};
///
/// // Automatically detect available hardware
/// let provider = detect_platform()?;
///
/// // Generate key in hardware
/// let key_handle = provider.generate_key()?;
///
/// // Sign data (key never leaves hardware)
/// let signature = provider.sign(key_handle, b"data to sign")?;
///
/// // Get public key for verification
/// let public_key = provider.get_public_key(key_handle)?;
/// ```
pub trait SecureKeyProvider: Send + Sync {
    /// Get a human-readable name for this provider
    ///
    /// Examples: "TPM 2.0", "Software (Development)", "ATECC608"
    fn name(&self) -> &str;

    /// Get the security level of this provider
    fn security_level(&self) -> SecurityLevel;

    /// Check if hardware is available and functional
    ///
    /// This should perform a quick health check without
    /// generating keys or performing expensive operations.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if hardware is ready
    /// - `Err(WSError)` if hardware is unavailable or misconfigured
    fn health_check(&self) -> Result<(), WSError>;

    /// Generate a new key pair in hardware
    ///
    /// The private key is generated within the secure hardware and
    /// never exposed. Only a handle is returned.
    ///
    /// # Security
    ///
    /// - Uses hardware RNG for key generation
    /// - Private key never leaves hardware
    /// - Key is protected by hardware security features
    ///
    /// # Returns
    ///
    /// A handle to the newly generated key
    ///
    /// # Errors
    ///
    /// - `WSError::HardwareError` if key generation fails
    /// - `WSError::NoSpace` if hardware key storage is full
    fn generate_key(&self) -> Result<KeyHandle, WSError>;

    /// Load an existing key by identifier
    ///
    /// # Arguments
    ///
    /// * `key_id` - Platform-specific key identifier
    ///
    /// # Returns
    ///
    /// A handle to the existing key
    ///
    /// # Errors
    ///
    /// - `WSError::KeyNotFound` if key doesn't exist
    /// - `WSError::AccessDenied` if key access is restricted
    fn load_key(&self, key_id: &str) -> Result<KeyHandle, WSError>;

    /// Sign data using a hardware-backed key
    ///
    /// # Security
    ///
    /// - Signing operation performed entirely within hardware
    /// - Private key never exposed to application
    /// - Signature format depends on key type (Ed25519, ECDSA P-256, etc.)
    ///
    /// # Arguments
    ///
    /// * `handle` - Handle to the signing key
    /// * `data` - Data to sign
    ///
    /// # Returns
    ///
    /// The cryptographic signature
    ///
    /// # Errors
    ///
    /// - `WSError::InvalidKeyHandle` if handle is invalid
    /// - `WSError::HardwareError` if signing fails
    fn sign(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, WSError>;

    /// Get the public key corresponding to a private key handle
    ///
    /// # Arguments
    ///
    /// * `handle` - Handle to the key
    ///
    /// # Returns
    ///
    /// The public key (safe to expose)
    ///
    /// # Errors
    ///
    /// - `WSError::InvalidKeyHandle` if handle is invalid
    fn get_public_key(&self, handle: KeyHandle) -> Result<PublicKey, WSError>;

    /// Get attestation data proving key is hardware-backed
    ///
    /// This provides cryptographic proof that a key was generated
    /// in and is protected by specific hardware.
    ///
    /// # Optional
    ///
    /// Not all platforms support attestation. Returns `None` for
    /// software-based implementations.
    ///
    /// # Arguments
    ///
    /// * `handle` - Handle to the key
    ///
    /// # Returns
    ///
    /// Attestation data if supported, `None` otherwise
    fn attestation(&self, handle: KeyHandle) -> Result<Option<Attestation>, WSError> {
        let _ = handle; // Suppress unused warning
        Ok(None) // Default: no attestation
    }

    /// Delete a key from hardware storage
    ///
    /// # Security
    ///
    /// This operation should be permanent and unrecoverable.
    ///
    /// # Arguments
    ///
    /// * `handle` - Handle to the key to delete
    ///
    /// # Errors
    ///
    /// - `WSError::InvalidKeyHandle` if handle is invalid
    /// - `WSError::HardwareError` if deletion fails
    fn delete_key(&self, handle: KeyHandle) -> Result<(), WSError>;

    /// List all available key handles
    ///
    /// # Security
    ///
    /// Only returns handles, never key material.
    ///
    /// # Returns
    ///
    /// Vector of key handles
    fn list_keys(&self) -> Result<Vec<KeyHandle>, WSError>;
}

/// Security level of a key provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Software-only (development/testing)
    ///
    /// Keys stored in process memory, no hardware protection.
    /// **NOT SUITABLE FOR PRODUCTION**
    Software = 0,

    /// Hardware-assisted (basic protection)
    ///
    /// Keys in hardware but limited security features.
    /// Example: Basic secure element without attestation
    HardwareBasic = 1,

    /// Hardware-backed (production-ready)
    ///
    /// Keys in certified hardware with security guarantees.
    /// Example: TPM 2.0, FIPS 140-2 Level 2 secure element
    HardwareBacked = 2,

    /// Hardware-certified (high security)
    ///
    /// Keys in certified hardware with attestation support.
    /// Example: TPM 2.0 + PCR policies, FIPS 140-2 Level 3
    HardwareCertified = 3,
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityLevel::Software => write!(f, "Software (Development Only)"),
            SecurityLevel::HardwareBasic => write!(f, "Hardware-Assisted"),
            SecurityLevel::HardwareBacked => write!(f, "Hardware-Backed (Production)"),
            SecurityLevel::HardwareCertified => write!(f, "Hardware-Certified (High Security)"),
        }
    }
}

/// Automatically detect and return the best available hardware provider
///
/// This function probes for available hardware in the following order:
/// 1. TPM 2.0 (if available)
/// 2. Secure Element (if available)
/// 3. TrustZone (if on ARM with OP-TEE)
/// 4. Software (fallback)
///
/// # Returns
///
/// A boxed trait object implementing `SecureKeyProvider`
///
/// # Errors
///
/// Only returns error if NO providers are available (should never happen
/// as software provider is always available).
pub fn detect_platform() -> Result<Box<dyn SecureKeyProvider>, WSError> {
    #[cfg(feature = "tpm2")]
    {
        if let Ok(provider) = tpm2::Tpm2Provider::new() {
            log::info!("Detected TPM 2.0 hardware");
            return Ok(Box::new(provider));
        }
    }

    #[cfg(feature = "secure-element")]
    {
        if let Ok(provider) = secure_element::SecureElementProvider::new() {
            log::info!("Detected secure element hardware");
            return Ok(Box::new(provider));
        }
    }

    #[cfg(feature = "trustzone")]
    {
        if let Ok(provider) = trustzone::TrustZoneProvider::new() {
            log::info!("Detected ARM TrustZone");
            return Ok(Box::new(provider));
        }
    }

    #[cfg(feature = "software-keys")]
    {
        log::warn!("No hardware security detected, using software keys (DEVELOPMENT ONLY)");
        Ok(Box::new(software::SoftwareProvider::new()))
    }

    #[cfg(not(feature = "software-keys"))]
    {
        Err(WSError::HardwareError(
            "No hardware security modules available".to_string(),
        ))
    }
}

/// Get all available providers on this platform
///
/// Unlike `detect_platform()`, this returns all working providers,
/// not just the best one.
///
/// # Returns
///
/// Vector of available providers with their names
pub fn list_available_providers() -> Vec<(String, Box<dyn SecureKeyProvider>)> {
    let mut providers = Vec::new();

    #[cfg(feature = "tpm2")]
    {
        if let Ok(provider) = tpm2::Tpm2Provider::new() {
            providers.push(("TPM 2.0".to_string(), Box::new(provider) as Box<dyn SecureKeyProvider>));
        }
    }

    #[cfg(feature = "secure-element")]
    {
        if let Ok(provider) = secure_element::SecureElementProvider::new() {
            providers.push((
                "Secure Element".to_string(),
                Box::new(provider) as Box<dyn SecureKeyProvider>,
            ));
        }
    }

    #[cfg(feature = "trustzone")]
    {
        if let Ok(provider) = trustzone::TrustZoneProvider::new() {
            providers.push((
                "TrustZone".to_string(),
                Box::new(provider) as Box<dyn SecureKeyProvider>,
            ));
        }
    }

    #[cfg(feature = "software-keys")]
    {
        providers.push((
            "Software (Development)".to_string(),
            Box::new(software::SoftwareProvider::new()) as Box<dyn SecureKeyProvider>,
        ));
    }

    providers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_handle_creation() {
        let handle = KeyHandle::from_raw(42);
        assert_eq!(handle.as_raw(), 42);
    }

    #[test]
    fn test_key_handle_equality() {
        let handle1 = KeyHandle::from_raw(42);
        let handle2 = KeyHandle::from_raw(42);
        let handle3 = KeyHandle::from_raw(43);

        assert_eq!(handle1, handle2);
        assert_ne!(handle1, handle3);
    }

    #[test]
    fn test_security_level_ordering() {
        assert!(SecurityLevel::Software < SecurityLevel::HardwareBasic);
        assert!(SecurityLevel::HardwareBasic < SecurityLevel::HardwareBacked);
        assert!(SecurityLevel::HardwareBacked < SecurityLevel::HardwareCertified);
    }

    #[test]
    fn test_security_level_display() {
        assert_eq!(
            SecurityLevel::Software.to_string(),
            "Software (Development Only)"
        );
        assert_eq!(
            SecurityLevel::HardwareCertified.to_string(),
            "Hardware-Certified (High Security)"
        );
    }

    #[test]
    fn test_detect_platform() {
        // Should always succeed with at least software provider
        let result = detect_platform();
        assert!(result.is_ok());

        let provider = result.unwrap();
        println!("Detected platform: {}", provider.name());
        println!("Security level: {}", provider.security_level());
    }

    #[test]
    fn test_list_available_providers() {
        let providers = list_available_providers();
        assert!(!providers.is_empty(), "Should have at least one provider");

        for (name, provider) in providers {
            println!("Available provider: {} ({})", name, provider.security_level());
        }
    }
}
