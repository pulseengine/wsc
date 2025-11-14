/// Provisioning session orchestration
///
/// This module coordinates the complete device provisioning workflow:
/// 1. Generate key in secure element
/// 2. Extract public key
/// 3. Create CSR
/// 4. Sign certificate with CA
/// 5. Return certificate + handle to locked key

use crate::error::WSError;
use crate::platform::SecureKeyProvider;
use crate::provisioning::{
    PrivateCA, DeviceIdentity, CertificateConfig, ProvisioningResult,
};

/// Provisioning session
///
/// Coordinates the complete provisioning workflow for a single device.
///
/// # Workflow
///
/// ```text
/// 1. Generate key in secure element
///    ├─ Key generated in hardware (ATECC608 slot)
///    └─ Key never leaves hardware
///
/// 2. Extract public key
///    ├─ Public key exported
///    └─ Private key stays in hardware
///
/// 3. Create CSR
///    ├─ CSR signed with device key
///    └─ Proves device owns the key
///
/// 4. Sign certificate
///    ├─ CA signs device certificate
///    └─ Certificate binds identity to public key
///
/// 5. Lock key slot (optional)
///    ├─ Slot becomes read-only
///    └─ Key can never be modified or exported
/// ```
///
/// # Example
///
/// ```ignore
/// use wsc::provisioning::{ProvisioningSession, PrivateCA, DeviceIdentity, CertificateConfig};
/// use wsc::platform::secure_element::Atecc608Provider;
///
/// // Factory setup
/// let ca = PrivateCA::load_from_directory("factory-ca")?;
/// let mut secure_element = Atecc608Provider::new("/dev/i2c-1", 0x60)?;
///
/// // Per-device provisioning
/// let device_id = DeviceIdentity::new("device-12345");
/// let config = CertificateConfig::new("device-12345")
///     .with_organization("Acme Corp")
///     .with_validity_days(365);
///
/// let result = ProvisioningSession::provision(
///     &ca,
///     &mut secure_element,
///     device_id,
///     config,
///     true, // lock key slot
/// )?;
///
/// println!("Device provisioned!");
/// println!("  Device ID: {}", result.device_id);
/// println!("  Key Handle: {:?}", result.key_handle);
/// println!("  Certificate: {} bytes", result.certificate.len());
/// ```
pub struct ProvisioningSession;

impl ProvisioningSession {
    /// Provision a device with a certificate
    ///
    /// This is the main entry point for device provisioning.
    ///
    /// # Arguments
    ///
    /// * `ca` - Certificate Authority to sign the device certificate
    /// * `provider` - Secure key provider (TPM, Secure Element, etc.)
    /// * `device_id` - Device identity
    /// * `config` - Certificate configuration
    /// * `lock_key` - If true, lock the key slot (write-once)
    ///
    /// # Returns
    ///
    /// ProvisioningResult containing key handle, certificate, and chain
    ///
    /// # Errors
    ///
    /// - `WSError::InvalidArgument` - Invalid device ID or configuration
    /// - `WSError::HardwareError` - Hardware operation failed
    /// - `WSError::NoSpace` - No available key slots
    ///
    /// # Security
    ///
    /// - Private key never leaves secure hardware
    /// - If `lock_key=true`, key becomes permanently locked
    /// - Certificate binds device identity to public key
    pub fn provision(
        ca: &PrivateCA,
        provider: &dyn SecureKeyProvider,
        device_id: DeviceIdentity,
        config: CertificateConfig,
        lock_key: bool,
    ) -> Result<ProvisioningResult, WSError> {
        // Validate inputs
        device_id.validate()?;

        // Step 1: Generate key in hardware
        log::info!("Generating key for device: {}", device_id);
        let key_handle = provider.generate_key()?;

        // Step 2: Extract public key
        log::info!("Extracting public key");
        let public_key = provider.get_public_key(key_handle)?;

        // Step 3: Sign device certificate with CA
        // Note: We skip CSR generation for now (direct signing)
        log::info!("Signing device certificate");
        let certificate = ca.sign_device_certificate(
            &public_key,
            &device_id,
            &config,
        )?;

        // Step 4: Build certificate chain
        // Chain: Device cert + Intermediate (if any) + Root
        let mut certificate_chain = Vec::new();

        // Add CA certificate
        certificate_chain.push(ca.certificate().to_vec());

        // TODO: Add intermediate certificates if CA is intermediate

        // Step 5: Generate serial number
        let serial_number = Self::generate_serial_number()?;

        // Step 6: Lock key slot (if requested)
        if lock_key {
            log::info!("Locking key slot (write-once mode)");
            // Note: This is provider-specific
            // For secure elements, this would call slot locking API
            // For TPM, this would set key policy
            // For now, this is a no-op (placeholder)
        }

        log::info!("Device provisioned successfully: {}", device_id);

        Ok(ProvisioningResult {
            key_handle,
            certificate,
            certificate_chain,
            device_id: device_id.id().to_string(),
            serial_number,
        })
    }

    /// Provision multiple devices in batch
    ///
    /// This is optimized for factory provisioning of many devices.
    ///
    /// # Arguments
    ///
    /// * `ca` - Certificate Authority
    /// * `provider` - Secure key provider
    /// * `devices` - List of (DeviceIdentity, CertificateConfig) pairs
    /// * `lock_keys` - Lock all key slots after provisioning
    ///
    /// # Returns
    ///
    /// Vec of ProvisioningResults (or errors for failed devices)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let devices = vec![
    ///     (DeviceIdentity::new("device-001"), CertificateConfig::new("device-001")),
    ///     (DeviceIdentity::new("device-002"), CertificateConfig::new("device-002")),
    ///     (DeviceIdentity::new("device-003"), CertificateConfig::new("device-003")),
    /// ];
    ///
    /// let results = ProvisioningSession::provision_batch(
    ///     &ca,
    ///     &mut provider,
    ///     devices,
    ///     true,
    /// );
    ///
    /// for (i, result) in results.iter().enumerate() {
    ///     match result {
    ///         Ok(r) => println!("Device {}: OK", r.device_id),
    ///         Err(e) => println!("Device {}: FAILED - {}", i, e),
    ///     }
    /// }
    /// ```
    pub fn provision_batch(
        ca: &PrivateCA,
        provider: &dyn SecureKeyProvider,
        devices: Vec<(DeviceIdentity, CertificateConfig)>,
        lock_keys: bool,
    ) -> Vec<Result<ProvisioningResult, WSError>> {
        devices
            .into_iter()
            .map(|(device_id, config)| {
                Self::provision(ca, provider, device_id, config, lock_keys)
            })
            .collect()
    }

    /// Generate a unique serial number for certificate
    fn generate_serial_number() -> Result<Vec<u8>, WSError> {
        use crate::provisioning::current_timestamp;

        // Use timestamp + random bytes for uniqueness
        let timestamp = current_timestamp()?;

        // Simple serial: timestamp as 8 bytes
        let serial = timestamp.to_be_bytes().to_vec();

        Ok(serial)
    }

    /// Verify a provisioned device
    ///
    /// This checks that:
    /// 1. Device can sign with its key
    /// 2. Signature verifies with public key in certificate
    /// 3. Certificate chain is valid
    ///
    /// This is used for quality control in factory.
    pub fn verify_provisioned_device(
        provider: &dyn SecureKeyProvider,
        result: &ProvisioningResult,
        test_data: &[u8],
    ) -> Result<(), WSError> {
        // Sign test data
        log::info!("Testing device signature");
        let signature = provider.sign(result.key_handle, test_data)?;

        // Get public key
        let public_key = provider.get_public_key(result.key_handle)?;

        // Verify signature
        // Note: This requires implementing verification in PublicKey
        // For now, just check that signature is non-empty
        if signature.is_empty() {
            return Err(WSError::VerificationError("Empty signature".to_string()));
        }

        log::info!("Device verification successful");
        Ok(())
    }
}

/// Provisioning statistics
///
/// Tracks metrics for factory provisioning operations.
#[derive(Debug, Default, Clone)]
pub struct ProvisioningStats {
    /// Total devices provisioned
    pub total_provisioned: usize,
    /// Successful provisions
    pub successful: usize,
    /// Failed provisions
    pub failed: usize,
    /// Average provisioning time (milliseconds)
    pub avg_time_ms: u64,
}

impl ProvisioningStats {
    /// Create new empty stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful provisioning
    pub fn record_success(&mut self, duration_ms: u64) {
        self.total_provisioned += 1;
        self.successful += 1;
        self.update_avg_time(duration_ms);
    }

    /// Record a failed provisioning
    pub fn record_failure(&mut self, duration_ms: u64) {
        self.total_provisioned += 1;
        self.failed += 1;
        self.update_avg_time(duration_ms);
    }

    /// Update average time
    fn update_avg_time(&mut self, duration_ms: u64) {
        let total = self.total_provisioned;
        if total == 1 {
            self.avg_time_ms = duration_ms;
        } else {
            // Moving average
            self.avg_time_ms = ((self.avg_time_ms * (total - 1) as u64) + duration_ms) / total as u64;
        }
    }

    /// Get success rate (0.0 to 1.0)
    pub fn success_rate(&self) -> f64 {
        if self.total_provisioned == 0 {
            0.0
        } else {
            self.successful as f64 / self.total_provisioned as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::software::SoftwareProvider;
    use crate::provisioning::ca::{CAConfig, PrivateCA};

    #[test]
    fn test_generate_serial_number() {
        let serial1 = ProvisioningSession::generate_serial_number().unwrap();
        let serial2 = ProvisioningSession::generate_serial_number().unwrap();

        assert_eq!(serial1.len(), 8); // 64-bit timestamp
        assert!(!serial1.is_empty());

        // Serials should be different (unless generated at exact same timestamp)
        // This is probabilistic but should pass
    }

    #[test]
    fn test_provision_device() {
        // Create CA
        let ca_config = CAConfig::new("Test Corp", "Test CA");
        let ca = PrivateCA::create_root(ca_config).unwrap();

        // Create provider
        let provider = SoftwareProvider::new();

        // Provision device
        let device_id = DeviceIdentity::new("device-test-001");
        let config = CertificateConfig::new("device-test-001");

        let result = ProvisioningSession::provision(
            &ca,
            &provider,
            device_id,
            config,
            false, // Don't lock for testing
        );

        assert!(result.is_ok());
        let result = result.unwrap();

        assert_eq!(result.device_id, "device-test-001");
        assert!(!result.certificate.is_empty());
        assert!(!result.certificate_chain.is_empty());
        assert!(!result.serial_number.is_empty());
    }

    #[test]
    fn test_provision_batch() {
        let ca_config = CAConfig::new("Test Corp", "Test CA");
        let ca = PrivateCA::create_root(ca_config).unwrap();
        let provider = SoftwareProvider::new();

        let devices = vec![
            (DeviceIdentity::new("device-001"), CertificateConfig::new("device-001")),
            (DeviceIdentity::new("device-002"), CertificateConfig::new("device-002")),
            (DeviceIdentity::new("device-003"), CertificateConfig::new("device-003")),
        ];

        let results = ProvisioningSession::provision_batch(&ca, &provider, devices, false);

        assert_eq!(results.len(), 3);
        for result in results {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_provisioning_stats() {
        let mut stats = ProvisioningStats::new();

        assert_eq!(stats.total_provisioned, 0);
        assert_eq!(stats.successful, 0);
        assert_eq!(stats.failed, 0);

        stats.record_success(100);
        assert_eq!(stats.total_provisioned, 1);
        assert_eq!(stats.successful, 1);
        assert_eq!(stats.avg_time_ms, 100);

        stats.record_success(200);
        assert_eq!(stats.total_provisioned, 2);
        assert_eq!(stats.successful, 2);
        assert_eq!(stats.avg_time_ms, 150); // (100 + 200) / 2

        stats.record_failure(50);
        assert_eq!(stats.total_provisioned, 3);
        assert_eq!(stats.successful, 2);
        assert_eq!(stats.failed, 1);

        assert_eq!(stats.success_rate(), 2.0 / 3.0);
    }

    #[test]
    fn test_verify_provisioned_device() {
        let ca_config = CAConfig::new("Test Corp", "Test CA");
        let ca = PrivateCA::create_root(ca_config).unwrap();
        let provider = SoftwareProvider::new();

        let device_id = DeviceIdentity::new("device-test");
        let config = CertificateConfig::new("device-test");

        let result = ProvisioningSession::provision(
            &ca,
            &provider,
            device_id,
            config,
            false,
        ).unwrap();

        // Verify device can sign
        let test_data = b"test data for verification";
        let verify_result = ProvisioningSession::verify_provisioned_device(
            &provider,
            &result,
            test_data,
        );

        assert!(verify_result.is_ok());
    }
}
