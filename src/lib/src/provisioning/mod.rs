/// Certificate provisioning for IoT devices
///
/// This module provides tools for provisioning certificates to IoT devices in
/// factory/manufacturing environments where internet connectivity is not available.
///
/// # Architecture
///
/// ```text
/// Factory Floor:
/// ┌─────────────────────────────────────────────────────────────┐
/// │ 1. Generate key IN secure element (ATECC608 slot)          │
/// │ 2. Extract public key                                       │
/// │ 3. Create CSR (Certificate Signing Request)                 │
/// │ 4. Sign with private CA (factory CA)                        │
/// │ 5. Inject certificate chain into device                     │
/// │ 6. Lock down slot (write-once, read-never)                  │
/// └─────────────────────────────────────────────────────────────┘
///                            ↓
/// Device in Field:
/// ┌─────────────────────────────────────────────────────────────┐
/// │ 1. Sign WASM with hardware key                              │
/// │ 2. Include certificate chain (not just public key)          │
/// │ 3. Verifier checks cert chain against embedded root CA      │
/// │ 4. No internet required                                     │
/// └─────────────────────────────────────────────────────────────┘
/// ```
///
/// # Security Model
///
/// Unlike keyless signing (Fulcio/Sigstore) which requires internet and OIDC,
/// this system uses a private Certificate Authority (CA) for offline verification:
///
/// - **Root CA**: Long-lived (10+ years), kept offline in HSM
/// - **Intermediate CA**: Medium-lived (3-5 years), used for daily signing
/// - **Device Certificates**: Short-lived (1-2 years), unique per device
///
/// Trust chain: Root CA → Intermediate CA → Device Certificate
///
/// # Use Cases
///
/// 1. **Factory Provisioning**: Generate and inject certs during manufacturing
/// 2. **Offline Verification**: Verify signatures without internet
/// 3. **Device Identity**: Each device has unique certificate with device ID
/// 4. **Hardware-Backed Keys**: Keys never leave secure element
///
/// # Example
///
/// ```ignore
/// use wsc::provisioning::{PrivateCA, DeviceIdentity, ProvisioningSession};
/// use wsc::platform::secure_element::Atecc608Provider;
///
/// // Factory setup (one-time)
/// let ca = PrivateCA::load_or_create("factory-ca")?;
///
/// // Per-device provisioning
/// let device_id = DeviceIdentity::new("device-12345");
/// let mut secure_element = Atecc608Provider::new("/dev/i2c-1", 0x60)?;
///
/// let session = ProvisioningSession::new(ca, device_id, secure_element)?;
/// let certificate = session.provision()?;
///
/// // Certificate is now in device, key locked in secure element
/// ```

use crate::error::WSError;
use crate::platform::KeyHandle;
use std::time::{SystemTime, UNIX_EPOCH};

pub mod ca;
pub mod csr;
pub mod device;
pub mod session;
pub mod verification;

pub use ca::PrivateCA;
pub use csr::CertificateSigningRequest;
pub use device::DeviceIdentity;
pub use session::ProvisioningSession;
pub use verification::OfflineVerifier;

/// Configuration for certificate generation
#[derive(Debug, Clone)]
pub struct CertificateConfig {
    /// Device identifier (embedded in certificate Subject)
    pub device_id: String,
    /// Organization name
    pub organization: String,
    /// Organizational unit (e.g., "IoT Devices")
    pub organizational_unit: Option<String>,
    /// Certificate validity period in days
    pub validity_days: u32,
    /// Optional serial number (auto-generated if None)
    pub serial_number: Option<Vec<u8>>,
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            device_id: String::new(),
            organization: "Example Organization".to_string(),
            organizational_unit: Some("IoT Devices".to_string()),
            validity_days: 365, // 1 year
            serial_number: None,
        }
    }
}

impl CertificateConfig {
    /// Create a new certificate configuration for a device
    pub fn new(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            ..Default::default()
        }
    }

    /// Set organization name
    pub fn with_organization(mut self, org: impl Into<String>) -> Self {
        self.organization = org.into();
        self
    }

    /// Set organizational unit
    pub fn with_organizational_unit(mut self, ou: impl Into<String>) -> Self {
        self.organizational_unit = Some(ou.into());
        self
    }

    /// Set certificate validity period in days
    pub fn with_validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }
}

/// Result of a successful provisioning operation
#[derive(Debug, Clone)]
pub struct ProvisioningResult {
    /// Handle to the key in secure hardware
    pub key_handle: KeyHandle,
    /// DER-encoded device certificate
    pub certificate: Vec<u8>,
    /// DER-encoded certificate chain (intermediate + root)
    pub certificate_chain: Vec<Vec<u8>>,
    /// Device identifier
    pub device_id: String,
    /// Certificate serial number
    pub serial_number: Vec<u8>,
}

impl ProvisioningResult {
    /// Get the complete certificate chain including device cert
    pub fn full_chain(&self) -> Vec<Vec<u8>> {
        let mut chain = vec![self.certificate.clone()];
        chain.extend(self.certificate_chain.iter().cloned());
        chain
    }

    /// Encode certificate chain as PEM
    pub fn to_pem(&self) -> Result<String, WSError> {
        use pem::Pem;

        let mut pem_output = String::new();

        // Add device certificate
        let device_pem = Pem::new("CERTIFICATE", self.certificate.clone());
        pem_output.push_str(&pem::encode(&device_pem));
        pem_output.push('\n');

        // Add chain certificates
        for cert_der in &self.certificate_chain {
            let cert_pem = Pem::new("CERTIFICATE", cert_der.clone());
            pem_output.push_str(&pem::encode(&cert_pem));
            pem_output.push('\n');
        }

        Ok(pem_output)
    }
}

/// Utility to get current Unix timestamp
pub(crate) fn current_timestamp() -> Result<u64, WSError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| WSError::InvalidArgument)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_config_default() {
        let config = CertificateConfig::default();
        assert_eq!(config.organization, "Example Organization");
        assert_eq!(config.validity_days, 365);
    }

    #[test]
    fn test_certificate_config_builder() {
        let config = CertificateConfig::new("device-123")
            .with_organization("Acme Corp")
            .with_organizational_unit("Manufacturing")
            .with_validity_days(730);

        assert_eq!(config.device_id, "device-123");
        assert_eq!(config.organization, "Acme Corp");
        assert_eq!(config.organizational_unit, Some("Manufacturing".to_string()));
        assert_eq!(config.validity_days, 730);
    }

    #[test]
    fn test_provisioning_result_full_chain() {
        let result = ProvisioningResult {
            key_handle: KeyHandle::from_raw(1),
            certificate: vec![1, 2, 3],
            certificate_chain: vec![vec![4, 5, 6], vec![7, 8, 9]],
            device_id: "device-1".to_string(),
            serial_number: vec![0x01],
        };

        let full_chain = result.full_chain();
        assert_eq!(full_chain.len(), 3);
        assert_eq!(full_chain[0], vec![1, 2, 3]); // Device cert
        assert_eq!(full_chain[1], vec![4, 5, 6]); // Intermediate
        assert_eq!(full_chain[2], vec![7, 8, 9]); // Root
    }

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp();
        assert!(ts.is_ok());

        let timestamp = ts.unwrap();
        // Should be reasonable (after 2020, before 2100)
        assert!(timestamp > 1577836800); // 2020-01-01
        assert!(timestamp < 4102444800); // 2100-01-01
    }
}
