/// Private Certificate Authority (CA) management
///
/// This module provides tools for operating a private CA for IoT device provisioning.
/// Unlike public CAs (Fulcio/Sigstore), this CA is operated by the device manufacturer
/// for offline certificate issuance.
///
/// # Security Model
///
/// - **Root CA**: Long-lived (10+ years), kept offline in HSM, only for signing intermediates
/// - **Intermediate CA**: Medium-lived (3-5 years), used daily for device cert signing
/// - **Device Certificates**: Short-lived (1-2 years), one per device
///
/// # Trust Chain
///
/// ```text
/// Root CA (offline, HSM)
///   ↓ signs
/// Intermediate CA (online, factory)
///   ↓ signs
/// Device Certificate (embedded in device)
/// ```

use crate::error::WSError;
use crate::provisioning::{CertificateConfig, DeviceIdentity};
use crate::signature::{KeyPair, PublicKey};
use std::path::Path;
use std::fs;
use base64::Engine;

/// Private Certificate Authority
///
/// This represents either a Root CA or Intermediate CA.
/// In production, Root CA should be kept offline in an HSM.
pub struct PrivateCA {
    /// CA key pair
    keypair: KeyPair,
    /// CA certificate (DER-encoded)
    certificate: Vec<u8>,
    /// CA type (Root or Intermediate)
    ca_type: CAType,
    /// CA configuration
    config: CAConfig,
}

/// Type of Certificate Authority
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CAType {
    /// Root CA (self-signed, offline)
    Root,
    /// Intermediate CA (signed by Root, online)
    Intermediate,
}

/// Configuration for a Certificate Authority
#[derive(Debug, Clone)]
pub struct CAConfig {
    /// Organization name
    pub organization: String,
    /// Common name (e.g., "Acme Corp Root CA")
    pub common_name: String,
    /// Country code (2 letters, e.g., "US")
    pub country: Option<String>,
    /// State/Province
    pub state: Option<String>,
    /// Locality/City
    pub locality: Option<String>,
    /// Certificate validity in days
    pub validity_days: u32,
}

impl Default for CAConfig {
    fn default() -> Self {
        Self {
            organization: "Example Organization".to_string(),
            common_name: "Example Root CA".to_string(),
            country: None,
            state: None,
            locality: None,
            validity_days: 3650, // 10 years for root CA
        }
    }
}

impl CAConfig {
    /// Create a new CA configuration
    pub fn new(organization: impl Into<String>, common_name: impl Into<String>) -> Self {
        Self {
            organization: organization.into(),
            common_name: common_name.into(),
            ..Default::default()
        }
    }

    /// Set country
    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        self.country = Some(country.into());
        self
    }

    /// Set state/province
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// Set locality/city
    pub fn with_locality(mut self, locality: impl Into<String>) -> Self {
        self.locality = Some(locality.into());
        self
    }

    /// Set validity period
    pub fn with_validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }
}

impl PrivateCA {
    /// Create a new Root CA
    ///
    /// This generates a new key pair and self-signed certificate.
    ///
    /// # Security
    ///
    /// In production, this should be done on an air-gapped machine with HSM.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = CAConfig::new("Acme Corp", "Acme Root CA")
    ///     .with_country("US")
    ///     .with_validity_days(3650); // 10 years
    ///
    /// let root_ca = PrivateCA::create_root(config)?;
    /// root_ca.save_to_directory("ca/")?;
    /// ```
    pub fn create_root(config: CAConfig) -> Result<Self, WSError> {
        // Generate CA key pair
        let keypair = KeyPair::generate();

        // Create self-signed certificate
        let certificate = Self::create_self_signed_cert(&keypair, &config)?;

        Ok(Self {
            keypair,
            certificate,
            ca_type: CAType::Root,
            config,
        })
    }

    /// Create an Intermediate CA signed by a Root CA
    ///
    /// # Example
    ///
    /// ```ignore
    /// let intermediate_config = CAConfig::new("Acme Corp", "Acme Intermediate CA")
    ///     .with_validity_days(1825); // 5 years
    ///
    /// let intermediate_ca = PrivateCA::create_intermediate(&root_ca, intermediate_config)?;
    /// ```
    pub fn create_intermediate(root_ca: &PrivateCA, config: CAConfig) -> Result<Self, WSError> {
        if root_ca.ca_type != CAType::Root {
            return Err(WSError::InvalidArgument);
        }

        // Generate intermediate key pair
        let keypair = KeyPair::generate();

        // Create certificate signed by root
        let certificate = Self::create_signed_cert(&keypair, root_ca, &config)?;

        Ok(Self {
            keypair,
            certificate,
            ca_type: CAType::Intermediate,
            config,
        })
    }

    /// Sign a device certificate
    ///
    /// # Arguments
    ///
    /// * `device_public_key` - Public key from device (in secure element)
    /// * `device_id` - Device identity
    /// * `cert_config` - Certificate configuration
    ///
    /// # Returns
    ///
    /// DER-encoded device certificate
    ///
    /// # Example
    ///
    /// ```ignore
    /// let public_key = provider.get_public_key(device_key_handle)?;
    /// let device_id = DeviceIdentity::new("device-123");
    /// let cert_config = CertificateConfig::new("device-123");
    ///
    /// let device_cert = ca.sign_device_certificate(
    ///     &public_key,
    ///     &device_id,
    ///     &cert_config
    /// )?;
    /// ```
    pub fn sign_device_certificate(
        &self,
        device_public_key: &PublicKey,
        device_id: &DeviceIdentity,
        cert_config: &CertificateConfig,
    ) -> Result<Vec<u8>, WSError> {
        // Validate device ID
        device_id.validate()?;

        // Create device certificate signed by this CA
        Self::create_device_cert(device_public_key, self, device_id, cert_config)
    }

    /// Create self-signed certificate (for Root CA)
    fn create_self_signed_cert(keypair: &KeyPair, config: &CAConfig) -> Result<Vec<u8>, WSError> {
        // Placeholder: Real implementation would use `rcgen` or similar
        // For now, return a mock certificate
        log::warn!("CA certificate generation not fully implemented (using placeholder)");

        // Create a minimal placeholder certificate
        let placeholder_cert = format!(
            "PLACEHOLDER_CERT:{}:{}",
            config.organization,
            config.common_name
        );

        Ok(placeholder_cert.into_bytes())
    }

    /// Create certificate signed by another CA
    fn create_signed_cert(
        keypair: &KeyPair,
        issuer: &PrivateCA,
        config: &CAConfig,
    ) -> Result<Vec<u8>, WSError> {
        // Placeholder
        log::warn!("CA certificate signing not fully implemented (using placeholder)");

        let placeholder_cert = format!(
            "PLACEHOLDER_CERT:{}:{}:SIGNED_BY:{}",
            config.organization,
            config.common_name,
            issuer.config.common_name
        );

        Ok(placeholder_cert.into_bytes())
    }

    /// Create device certificate
    fn create_device_cert(
        device_public_key: &PublicKey,
        ca: &PrivateCA,
        device_id: &DeviceIdentity,
        config: &CertificateConfig,
    ) -> Result<Vec<u8>, WSError> {
        // Placeholder
        log::warn!("Device certificate generation not fully implemented (using placeholder)");

        let placeholder_cert = format!(
            "PLACEHOLDER_DEVICE_CERT:{}:SIGNED_BY:{}",
            device_id.id(),
            ca.config.common_name
        );

        Ok(placeholder_cert.into_bytes())
    }

    /// Get CA certificate (DER)
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// Get CA certificate as PEM
    pub fn certificate_pem(&self) -> String {
        use pem::Pem;
        let pem = Pem::new("CERTIFICATE", self.certificate.clone());
        pem::encode(&pem)
    }

    /// Get CA type
    pub fn ca_type(&self) -> CAType {
        self.ca_type
    }

    /// Get CA configuration
    pub fn config(&self) -> &CAConfig {
        &self.config
    }

    /// Save CA to directory
    ///
    /// Saves:
    /// - `ca.key` - Private key (PEM, encrypted)
    /// - `ca.crt` - Certificate (PEM)
    ///
    /// # Security
    ///
    /// IMPORTANT: Protect the CA private key!
    /// - Store on encrypted filesystem
    /// - Restrict file permissions (0600)
    /// - For Root CA, keep offline in HSM
    pub fn save_to_directory(&self, dir: impl AsRef<Path>) -> Result<(), WSError> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir)
            .map_err(|e| WSError::HardwareError(format!("Failed to create directory: {}", e)))?;

        // Save private key
        let key_path = dir.join("ca.key");
        let key_pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::prelude::BASE64_STANDARD.encode(self.keypair.sk.to_bytes())
        );
        fs::write(&key_path, key_pem)
            .map_err(|e| WSError::HardwareError(format!("Failed to write key: {}", e)))?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&key_path)
                .map_err(|e| WSError::HardwareError(format!("Failed to get metadata: {}", e)))?
                .permissions();
            perms.set_mode(0o600); // Owner read/write only
            fs::set_permissions(&key_path, perms)
                .map_err(|e| WSError::HardwareError(format!("Failed to set permissions: {}", e)))?;
        }

        // Save certificate
        let cert_path = dir.join("ca.crt");
        fs::write(cert_path, self.certificate_pem())
            .map_err(|e| WSError::HardwareError(format!("Failed to write certificate: {}", e)))?;

        Ok(())
    }

    /// Load CA from directory
    pub fn load_from_directory(dir: impl AsRef<Path>) -> Result<Self, WSError> {
        // Placeholder for now
        Err(WSError::UnsupportedAlgorithm(
            "CA loading not yet implemented (placeholder)".to_string()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_config_builder() {
        let config = CAConfig::new("Acme Corp", "Acme Root CA")
            .with_country("US")
            .with_state("California")
            .with_locality("San Francisco")
            .with_validity_days(3650);

        assert_eq!(config.organization, "Acme Corp");
        assert_eq!(config.common_name, "Acme Root CA");
        assert_eq!(config.country, Some("US".to_string()));
        assert_eq!(config.state, Some("California".to_string()));
        assert_eq!(config.locality, Some("San Francisco".to_string()));
        assert_eq!(config.validity_days, 3650);
    }

    #[test]
    fn test_create_root_ca() {
        let config = CAConfig::new("Test Corp", "Test Root CA");
        let ca = PrivateCA::create_root(config).unwrap();

        assert_eq!(ca.ca_type(), CAType::Root);
        assert_eq!(ca.config().organization, "Test Corp");
        assert_eq!(ca.config().common_name, "Test Root CA");
        assert!(!ca.certificate().is_empty());
    }

    #[test]
    fn test_create_intermediate_ca() {
        let root_config = CAConfig::new("Test Corp", "Test Root CA");
        let root_ca = PrivateCA::create_root(root_config).unwrap();

        let intermediate_config = CAConfig::new("Test Corp", "Test Intermediate CA")
            .with_validity_days(1825);
        let intermediate_ca = PrivateCA::create_intermediate(&root_ca, intermediate_config).unwrap();

        assert_eq!(intermediate_ca.ca_type(), CAType::Intermediate);
        assert_eq!(intermediate_ca.config().common_name, "Test Intermediate CA");
    }

    #[test]
    fn test_cannot_create_intermediate_from_intermediate() {
        let root_config = CAConfig::new("Test Corp", "Test Root CA");
        let root_ca = PrivateCA::create_root(root_config).unwrap();

        let intermediate_config = CAConfig::new("Test Corp", "Test Intermediate CA");
        let intermediate_ca = PrivateCA::create_intermediate(&root_ca, intermediate_config).unwrap();

        // Try to create intermediate from intermediate (should fail)
        let config2 = CAConfig::new("Test Corp", "Test Second Intermediate CA");
        let result = PrivateCA::create_intermediate(&intermediate_ca, config2);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_device_certificate() {
        let root_config = CAConfig::new("Test Corp", "Test Root CA");
        let ca = PrivateCA::create_root(root_config).unwrap();

        // Generate a device key
        let device_keypair = KeyPair::generate();
        let device_id = DeviceIdentity::new("device-123");
        let cert_config = CertificateConfig::new("device-123");

        let device_cert = ca.sign_device_certificate(
            &device_keypair.pk,
            &device_id,
            &cert_config,
        );

        assert!(device_cert.is_ok());
        assert!(!device_cert.unwrap().is_empty());
    }

    #[test]
    fn test_ca_certificate_pem() {
        let config = CAConfig::new("Test Corp", "Test Root CA");
        let ca = PrivateCA::create_root(config).unwrap();

        let pem = ca.certificate_pem();
        assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }
}
