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

// ============================================================================
// Hardware Abstraction Traits for Attestation
// ============================================================================
// These traits provide a focused interface for attestation signing/verification.
// They complement SecureKeyProvider with a simpler API for tools like Loom.

/// Signing algorithm used by hardware signers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// Ed25519 (EdDSA with Curve25519)
    Ed25519,
    /// ECDSA with P-256 curve (required by Sigstore/Fulcio)
    EcdsaP256,
    /// ECDSA with P-384 curve
    EcdsaP384,
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningAlgorithm::Ed25519 => write!(f, "ed25519"),
            SigningAlgorithm::EcdsaP256 => write!(f, "ecdsa-p256"),
            SigningAlgorithm::EcdsaP384 => write!(f, "ecdsa-p384"),
        }
    }
}

/// Trait for hardware-backed attestation signing.
///
/// This is a simplified interface for tools (like Loom, WAC) to sign
/// transformation attestations. It abstracts over:
/// - Software keys (development)
/// - TPM 2.0 (production Linux/Windows)
/// - Secure Elements (IoT/embedded: ATECC608, SE050)
/// - TrustZone (ARM)
///
/// # Example
///
/// ```ignore
/// use wsc::platform::HardwareSigner;
///
/// fn sign_attestation(signer: &dyn HardwareSigner, attestation_json: &[u8]) -> Vec<u8> {
///     signer.sign(attestation_json).expect("signing failed")
/// }
/// ```
///
/// # Security
///
/// Implementations MUST ensure private key material never leaves
/// the secure boundary (hardware module or secure enclave).
pub trait HardwareSigner: Send + Sync {
    /// Sign data using the hardware-protected key.
    ///
    /// The signing operation is performed entirely within the secure
    /// hardware boundary.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to sign (typically attestation JSON or PAE encoding)
    ///
    /// # Returns
    ///
    /// Raw signature bytes (format depends on algorithm)
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HardwareError>;

    /// Get the public key corresponding to this signer.
    ///
    /// Safe to expose - this is used for verification.
    fn public_key(&self) -> Result<Vec<u8>, HardwareError>;

    /// Get the signing algorithm.
    fn algorithm(&self) -> SigningAlgorithm;

    /// Get an optional key identifier.
    ///
    /// Used to help verifiers find the right public key.
    fn key_id(&self) -> Option<String> {
        None
    }

    /// Get the security level of this signer.
    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::Software
    }
}

/// Trait for hardware-accelerated verification.
///
/// This is important for embedded/constrained devices where software
/// crypto may be too slow or where hardware acceleration is available.
///
/// # Use Cases
///
/// - Embedded devices with crypto accelerators
/// - Secure elements that support verification
/// - TPMs with policy-based verification
///
/// # Example
///
/// ```ignore
/// use wsc::platform::HardwareVerifier;
///
/// fn verify_attestation(
///     verifier: &dyn HardwareVerifier,
///     data: &[u8],
///     signature: &[u8],
///     public_key: &[u8],
/// ) -> bool {
///     verifier.verify(data, signature, public_key).is_ok()
/// }
/// ```
pub trait HardwareVerifier: Send + Sync {
    /// Verify a signature using hardware acceleration.
    ///
    /// # Arguments
    ///
    /// * `data` - Original data that was signed
    /// * `signature` - Signature to verify
    /// * `public_key` - Public key to verify against
    ///
    /// # Returns
    ///
    /// - `Ok(())` if signature is valid
    /// - `Err(HardwareError::VerificationFailed)` if invalid
    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), HardwareError>;

    /// Get supported algorithms.
    fn supported_algorithms(&self) -> Vec<SigningAlgorithm>;

    /// Check if a specific algorithm is supported.
    fn supports_algorithm(&self, algorithm: SigningAlgorithm) -> bool {
        self.supported_algorithms().contains(&algorithm)
    }
}

/// Errors from hardware operations.
#[derive(Debug, Clone)]
pub enum HardwareError {
    /// Hardware not available or not initialized
    NotAvailable(String),
    /// Key not found
    KeyNotFound(String),
    /// Signing operation failed
    SigningFailed(String),
    /// Verification failed (signature invalid)
    VerificationFailed(String),
    /// Algorithm not supported by hardware
    UnsupportedAlgorithm(SigningAlgorithm),
    /// Hardware communication error
    CommunicationError(String),
    /// Access denied (permissions, policies)
    AccessDenied(String),
}

impl fmt::Display for HardwareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HardwareError::NotAvailable(msg) => write!(f, "Hardware not available: {}", msg),
            HardwareError::KeyNotFound(msg) => write!(f, "Key not found: {}", msg),
            HardwareError::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            HardwareError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            HardwareError::UnsupportedAlgorithm(alg) => {
                write!(f, "Algorithm not supported: {}", alg)
            }
            HardwareError::CommunicationError(msg) => write!(f, "Communication error: {}", msg),
            HardwareError::AccessDenied(msg) => write!(f, "Access denied: {}", msg),
        }
    }
}

impl std::error::Error for HardwareError {}

/// Software implementation of HardwareSigner for development/testing.
///
/// This wraps an Ed25519 secret key and provides the HardwareSigner interface.
/// **NOT suitable for production** - use only for testing and development.
pub struct SoftwareEd25519Signer {
    secret_key: ed25519_compact::SecretKey,
    key_id: Option<String>,
}

impl SoftwareEd25519Signer {
    /// Create from an existing Ed25519 secret key.
    pub fn from_secret_key(secret_key: ed25519_compact::SecretKey, key_id: Option<String>) -> Self {
        Self { secret_key, key_id }
    }

    /// Generate a new random keypair.
    pub fn generate(key_id: Option<String>) -> Self {
        let key_pair = ed25519_compact::KeyPair::generate();
        Self {
            secret_key: key_pair.sk,
            key_id,
        }
    }
}

impl HardwareSigner for SoftwareEd25519Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, HardwareError> {
        let signature = self.secret_key.sign(data, None);
        Ok(signature.as_ref().to_vec())
    }

    fn public_key(&self) -> Result<Vec<u8>, HardwareError> {
        Ok(self.secret_key.public_key().as_ref().to_vec())
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Ed25519
    }

    fn key_id(&self) -> Option<String> {
        self.key_id.clone()
    }

    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::Software
    }
}

/// Software implementation of HardwareVerifier for development/testing.
pub struct SoftwareEd25519Verifier;

impl SoftwareEd25519Verifier {
    /// Create a new software verifier.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SoftwareEd25519Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareVerifier for SoftwareEd25519Verifier {
    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), HardwareError> {
        if signature.len() != 64 {
            return Err(HardwareError::VerificationFailed(
                "Invalid signature length (expected 64 bytes)".to_string(),
            ));
        }
        if public_key.len() != 32 {
            return Err(HardwareError::VerificationFailed(
                "Invalid public key length (expected 32 bytes)".to_string(),
            ));
        }

        let sig = ed25519_compact::Signature::from_slice(signature).map_err(|e| {
            HardwareError::VerificationFailed(format!("Invalid signature format: {:?}", e))
        })?;

        let pk = ed25519_compact::PublicKey::from_slice(public_key).map_err(|e| {
            HardwareError::VerificationFailed(format!("Invalid public key format: {:?}", e))
        })?;

        pk.verify(data, &sig)
            .map_err(|_| HardwareError::VerificationFailed("Signature verification failed".to_string()))
    }

    fn supported_algorithms(&self) -> Vec<SigningAlgorithm> {
        vec![SigningAlgorithm::Ed25519]
    }
}

// ============================================================================
// End Hardware Abstraction Traits
// ============================================================================

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
        // Try common I2C bus paths
        for bus_path in &["/dev/i2c-1", "/dev/i2c-0", "/dev/i2c-2"] {
            if let Ok(provider) = secure_element::SecureElementProvider::auto_detect(bus_path) {
                log::info!("Detected secure element hardware on {}", bus_path);
                return Ok(Box::new(provider));
            }
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

    // TODO(tpm2): Add TPM 2.0 provider detection when implemented
    // TODO(sgx): Add SGX provider detection when implemented
    // TODO(trustzone): Add TrustZone provider detection when implemented
    // TODO(se050): Add SE050 provider detection when implemented

    #[cfg(feature = "secure-element")]
    {
        // Try common I2C bus paths
        for bus_path in &["/dev/i2c-1", "/dev/i2c-0", "/dev/i2c-2"] {
            if let Ok(provider) = secure_element::SecureElementProvider::auto_detect(bus_path) {
                providers.push((
                    format!("Secure Element ({})", bus_path),
                    Box::new(provider) as Box<dyn SecureKeyProvider>,
                ));
                break; // Only add first detected
            }
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

    // Hardware abstraction trait tests
    #[test]
    fn test_software_ed25519_signer() {
        let signer = SoftwareEd25519Signer::generate(Some("test-key".to_string()));

        // Test signing
        let data = b"test data to sign";
        let signature = signer.sign(data).expect("signing should succeed");
        assert_eq!(signature.len(), 64, "Ed25519 signature should be 64 bytes");

        // Test public key extraction
        let public_key = signer.public_key().expect("public key should be available");
        assert_eq!(public_key.len(), 32, "Ed25519 public key should be 32 bytes");

        // Test key ID
        assert_eq!(signer.key_id(), Some("test-key".to_string()));

        // Test algorithm
        assert_eq!(signer.algorithm(), SigningAlgorithm::Ed25519);

        // Test security level
        assert_eq!(signer.security_level(), SecurityLevel::Software);
    }

    #[test]
    fn test_software_ed25519_verifier() {
        let verifier = SoftwareEd25519Verifier::new();

        // Generate a keypair for testing
        let signer = SoftwareEd25519Signer::generate(None);
        let data = b"test data for verification";
        let signature = signer.sign(data).unwrap();
        let public_key = signer.public_key().unwrap();

        // Test successful verification
        assert!(verifier.verify(data, &signature, &public_key).is_ok());

        // Test failed verification with wrong data
        assert!(verifier.verify(b"wrong data", &signature, &public_key).is_err());

        // Test failed verification with corrupted signature
        let mut bad_sig = signature.clone();
        bad_sig[0] ^= 0xff;
        assert!(verifier.verify(data, &bad_sig, &public_key).is_err());

        // Test supported algorithms
        let algorithms = verifier.supported_algorithms();
        assert!(algorithms.contains(&SigningAlgorithm::Ed25519));
        assert!(verifier.supports_algorithm(SigningAlgorithm::Ed25519));
        assert!(!verifier.supports_algorithm(SigningAlgorithm::EcdsaP256));
    }

    #[test]
    fn test_signing_algorithm_display() {
        assert_eq!(SigningAlgorithm::Ed25519.to_string(), "ed25519");
        assert_eq!(SigningAlgorithm::EcdsaP256.to_string(), "ecdsa-p256");
        assert_eq!(SigningAlgorithm::EcdsaP384.to_string(), "ecdsa-p384");
    }

    #[test]
    fn test_hardware_error_display() {
        let err = HardwareError::NotAvailable("TPM not found".to_string());
        assert!(err.to_string().contains("Hardware not available"));
        assert!(err.to_string().contains("TPM not found"));

        let err = HardwareError::VerificationFailed("bad signature".to_string());
        assert!(err.to_string().contains("Verification failed"));

        let err = HardwareError::UnsupportedAlgorithm(SigningAlgorithm::EcdsaP384);
        assert!(err.to_string().contains("ecdsa-p384"));
    }

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
            println!(
                "Available provider: {} ({})",
                name,
                provider.security_level()
            );
        }
    }
}
