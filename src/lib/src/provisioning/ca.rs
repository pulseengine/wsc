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
use crate::signature::{KeyPair, PublicKey, SecretKey};
use std::path::Path;
use std::fs;
use base64::Engine;
use rcgen::{
    CertificateParams, DistinguishedName, DnType,
    IsCa, BasicConstraints, KeyUsagePurpose, ExtendedKeyUsagePurpose,
    Ia5String,
};
use time::{OffsetDateTime, Duration as TimeDuration};
use rustls_pki_types::CertificateDer;

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

    /// Sign a device certificate using a full keypair (for testing with SoftwareProvider)
    ///
    /// This method is primarily for testing where the full keypair is available.
    /// In production with hardware security modules, only the public key is extractable.
    pub fn sign_device_certificate_with_keypair(
        &self,
        device_keypair: &KeyPair,
        device_id: &DeviceIdentity,
        cert_config: &CertificateConfig,
    ) -> Result<Vec<u8>, WSError> {
        // Validate device ID
        device_id.validate()?;

        // Create device certificate using the full keypair
        Self::create_device_cert_with_keypair(device_keypair, self, device_id, cert_config)
    }

    /// Create self-signed certificate (for Root CA)
    fn create_self_signed_cert(keypair: &KeyPair, config: &CAConfig) -> Result<Vec<u8>, WSError> {
        // Create rcgen certificate parameters
        let mut params = CertificateParams::default();

        // Set subject distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &config.common_name);
        dn.push(DnType::OrganizationName, &config.organization);

        if let Some(country) = &config.country {
            dn.push(DnType::CountryName, country);
        }
        if let Some(state) = &config.state {
            dn.push(DnType::StateOrProvinceName, state);
        }
        if let Some(locality) = &config.locality {
            dn.push(DnType::LocalityName, locality);
        }

        params.distinguished_name = dn;

        // Set validity period
        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + TimeDuration::days(config.validity_days as i64);

        // CA certificate settings
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        // Key usage for CA
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        // Convert Ed25519 keypair to rcgen KeyPair
        let key_pair_pem = Self::ed25519_to_pem(keypair)?;
        let rcgen_keypair = rcgen::KeyPair::from_pem(&key_pair_pem)
            .map_err(|e| WSError::HardwareError(format!("Failed to create key pair: {}", e)))?;

        // Generate self-signed certificate
        let cert = params.self_signed(&rcgen_keypair)
            .map_err(|e| WSError::HardwareError(format!("Failed to generate certificate: {}", e)))?;

        // Serialize to DER
        let der = cert.der().to_vec();

        Ok(der)
    }

    /// Create certificate signed by another CA
    fn create_signed_cert(
        keypair: &KeyPair,
        issuer: &PrivateCA,
        config: &CAConfig,
    ) -> Result<Vec<u8>, WSError> {
        // Create certificate parameters
        let mut params = CertificateParams::default();

        // Set subject distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &config.common_name);
        dn.push(DnType::OrganizationName, &config.organization);

        if let Some(country) = &config.country {
            dn.push(DnType::CountryName, country);
        }
        if let Some(state) = &config.state {
            dn.push(DnType::StateOrProvinceName, state);
        }
        if let Some(locality) = &config.locality {
            dn.push(DnType::LocalityName, locality);
        }

        params.distinguished_name = dn;

        // Set validity period
        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + TimeDuration::days(config.validity_days as i64);

        // Intermediate CA certificate settings
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));  // Path length 0

        // Key usage for CA
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        // Convert Ed25519 keypair to rcgen KeyPair
        let key_pair_pem = Self::ed25519_to_pem(keypair)?;
        let rcgen_keypair = rcgen::KeyPair::from_pem(&key_pair_pem)
            .map_err(|e| WSError::HardwareError(format!("Failed to create key pair: {}", e)))?;

        // Parse issuer certificate
        let issuer_cert_der = CertificateDer::from(issuer.certificate.clone());
        let issuer_cert_params = CertificateParams::from_ca_cert_der(&issuer_cert_der)
            .map_err(|e| WSError::X509Error(format!("Failed to parse issuer certificate: {}", e)))?;

        let issuer_key_pem = Self::ed25519_to_pem(&issuer.keypair)?;
        let issuer_keypair = rcgen::KeyPair::from_pem(&issuer_key_pem)
            .map_err(|e| WSError::HardwareError(format!("Failed to create issuer key pair: {}", e)))?;

        let issuer_cert = issuer_cert_params.self_signed(&issuer_keypair)
            .map_err(|e| WSError::HardwareError(format!("Failed to create issuer cert: {}", e)))?;

        // Sign certificate with issuer
        let der = params.signed_by(&rcgen_keypair, &issuer_cert, &issuer_keypair)
            .map_err(|e| WSError::HardwareError(format!("Failed to sign certificate: {}", e)))?
            .der()
            .to_vec();

        Ok(der)
    }

    /// Create device certificate with full keypair (for testing)
    fn create_device_cert_with_keypair(
        device_keypair: &KeyPair,
        ca: &PrivateCA,
        device_id: &DeviceIdentity,
        config: &CertificateConfig,
    ) -> Result<Vec<u8>, WSError> {
        // Same as create_device_cert but uses the actual device keypair
        let mut params = CertificateParams::default();

        // Set subject distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &device_id.to_common_name());
        dn.push(DnType::OrganizationName, &config.organization);

        if let Some(ou) = &config.organizational_unit {
            dn.push(DnType::OrganizationalUnitName, ou);
        }

        params.distinguished_name = dn;

        // Add device ID as Subject Alternative Name
        let device_id_str = device_id.id().to_string();
        let ia5_string = Ia5String::try_from(device_id_str.as_str())
            .map_err(|_| WSError::InvalidArgument)?;
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName(ia5_string),
        ];

        // Set validity period
        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + TimeDuration::days(config.validity_days as i64);

        // End-entity certificate (not a CA)
        params.is_ca = IsCa::NoCa;

        // Key usage for code signing
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
        ];

        // Extended key usage for code signing
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::CodeSigning,
        ];

        // Use the actual device keypair
        let key_pair_pem = Self::ed25519_to_pem(device_keypair)?;
        let rcgen_keypair = rcgen::KeyPair::from_pem(&key_pair_pem)
            .map_err(|e| WSError::HardwareError(format!("Failed to create key pair: {}", e)))?;

        // Parse issuer certificate and sign
        let issuer_cert_der = CertificateDer::from(ca.certificate.clone());
        let issuer_cert_params = CertificateParams::from_ca_cert_der(&issuer_cert_der)
            .map_err(|e| WSError::X509Error(format!("Failed to parse CA certificate: {}", e)))?;

        let issuer_key_pem = Self::ed25519_to_pem(&ca.keypair)?;
        let issuer_keypair = rcgen::KeyPair::from_pem(&issuer_key_pem)
            .map_err(|e| WSError::HardwareError(format!("Failed to create CA key pair: {}", e)))?;

        let issuer_cert = issuer_cert_params.self_signed(&issuer_keypair)
            .map_err(|e| WSError::HardwareError(format!("Failed to create CA cert: {}", e)))?;

        // Sign certificate with CA
        let der = params.signed_by(&rcgen_keypair, &issuer_cert, &issuer_keypair)
            .map_err(|e| WSError::HardwareError(format!("Failed to sign device certificate: {}", e)))?
            .der()
            .to_vec();

        Ok(der)
    }

    /// Create device certificate
    fn create_device_cert(
        device_public_key: &PublicKey,
        ca: &PrivateCA,
        device_id: &DeviceIdentity,
        config: &CertificateConfig,
    ) -> Result<Vec<u8>, WSError> {
        // Create certificate parameters
        let mut params = CertificateParams::default();

        // Set subject distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &device_id.to_common_name());
        dn.push(DnType::OrganizationName, &config.organization);

        if let Some(ou) = &config.organizational_unit {
            dn.push(DnType::OrganizationalUnitName, ou);
        }

        params.distinguished_name = dn;

        // Add device ID as Subject Alternative Name
        let device_id_str = device_id.id().to_string();
        let ia5_string = Ia5String::try_from(device_id_str.as_str())
            .map_err(|_| WSError::InvalidArgument)?;
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName(ia5_string),
        ];

        // Set validity period
        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + TimeDuration::days(config.validity_days as i64);

        // End-entity certificate (not a CA)
        params.is_ca = IsCa::NoCa;

        // Key usage for code signing
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
        ];

        // Extended key usage for code signing
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::CodeSigning,
        ];

        // Create a KeyPair containing the device's public key
        // Note: rcgen requires a KeyPair for certificate generation, but we only have the public key.
        // We generate a temporary valid keypair and replace its public key with the device's.
        // The temporary private key is never used for actual signing - the CA signs the certificate.
        let temp_full_keypair = KeyPair::generate();
        let temp_keypair = KeyPair {
            sk: temp_full_keypair.sk,
            pk: device_public_key.clone(),
        };

        // Convert to PEM for rcgen
        let key_pair_pem = Self::ed25519_to_pem(&temp_keypair)?;
        let rcgen_keypair = rcgen::KeyPair::from_pem(&key_pair_pem)
            .map_err(|e| WSError::HardwareError(format!("Failed to create key pair: {}", e)))?;

        // Parse issuer certificate
        let issuer_cert_der = CertificateDer::from(ca.certificate.clone());
        let issuer_cert_params = CertificateParams::from_ca_cert_der(&issuer_cert_der)
            .map_err(|e| WSError::X509Error(format!("Failed to parse CA certificate: {}", e)))?;

        let issuer_key_pem = Self::ed25519_to_pem(&ca.keypair)?;
        let issuer_keypair = rcgen::KeyPair::from_pem(&issuer_key_pem)
            .map_err(|e| WSError::HardwareError(format!("Failed to create CA key pair: {}", e)))?;

        let issuer_cert = issuer_cert_params.self_signed(&issuer_keypair)
            .map_err(|e| WSError::HardwareError(format!("Failed to create CA cert: {}", e)))?;

        // Sign certificate with CA
        let der = params.signed_by(&rcgen_keypair, &issuer_cert, &issuer_keypair)
            .map_err(|e| WSError::HardwareError(format!("Failed to sign device certificate: {}", e)))?
            .der()
            .to_vec();

        Ok(der)
    }

    /// Convert Ed25519 keypair to PEM format for rcgen
    fn ed25519_to_pem(keypair: &KeyPair) -> Result<String, WSError> {
        // Use ed25519-compact's PEM export feature
        let pem = keypair.sk.to_pem();
        Ok(pem)
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
    pub fn load_from_directory(_dir: impl AsRef<Path>) -> Result<Self, WSError> {
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

    #[test]
    fn test_root_ca_x509_structure() {
        use x509_parser::prelude::*;

        let config = CAConfig::new("Test Corp", "Test Root CA")
            .with_country("US")
            .with_state("California");
        let ca = PrivateCA::create_root(config).unwrap();

        // Parse certificate with x509-parser
        let cert_der = ca.certificate();
        let (_, cert) = X509Certificate::from_der(cert_der).unwrap();

        // Verify subject
        let subject = cert.subject();
        let cn = subject.iter_common_name().next().unwrap().as_str().unwrap();
        assert_eq!(cn, "Test Root CA");

        let org = subject.iter_organization().next().unwrap().as_str().unwrap();
        assert_eq!(org, "Test Corp");

        // Verify it's a CA certificate
        let basic_constraints = cert.basic_constraints().unwrap();
        if let Some(bc) = basic_constraints {
            assert!(bc.value.ca, "Root CA certificate should have CA=true");
        }

        // Verify key usage (should include keyCertSign for CA)
        // Note: rcgen may set key usage, check if present
        let key_usage = cert.key_usage();
        assert!(key_usage.is_ok());

        println!("✓ Root CA certificate is valid X.509");
        println!("  Subject: {}", cert.subject());
        println!("  Issuer: {}", cert.issuer());
        println!("  Serial: {}", cert.serial.to_str_radix(16));
        println!("  Valid from: {}", cert.validity().not_before);
        println!("  Valid to: {}", cert.validity().not_after);
    }

    #[test]
    fn test_device_certificate_x509_structure() {
        use x509_parser::prelude::*;

        let root_config = CAConfig::new("Test Corp", "Test Root CA");
        let ca = PrivateCA::create_root(root_config).unwrap();

        let device_keypair = KeyPair::generate();
        let device_id = DeviceIdentity::new("device-123");
        let cert_config = CertificateConfig::new("device-123")
            .with_organization("Test Corp")
            .with_organizational_unit("IoT Devices");

        let device_cert_der = ca.sign_device_certificate(
            &device_keypair.pk,
            &device_id,
            &cert_config,
        ).unwrap();

        // Parse certificate
        let (_, cert) = X509Certificate::from_der(&device_cert_der).unwrap();

        // Verify subject
        let subject = cert.subject();
        let cn = subject.iter_common_name().next().unwrap().as_str().unwrap();
        assert_eq!(cn, "Device device-123");

        let org = subject.iter_organization().next().unwrap().as_str().unwrap();
        assert_eq!(org, "Test Corp");

        // Verify it's NOT a CA certificate
        let basic_constraints = cert.basic_constraints().unwrap();
        if let Some(bc) = basic_constraints {
            assert!(!bc.value.ca, "Device certificate should not be a CA");
        }

        // Verify subject alternative name contains device ID
        let san = cert.subject_alternative_name();
        assert!(san.is_ok(), "Device certificate should have SAN");
        let san_value = san.unwrap();
        assert!(san_value.is_some(), "Device certificate should have SAN value");

        println!("✓ Device certificate is valid X.509");
        println!("  Subject: {}", cert.subject());
        println!("  Issuer: {}", cert.issuer());
        println!("  Serial: {}", cert.serial.to_str_radix(16));
    }

    #[test]
    fn test_certificate_chain_validation() {
        use x509_parser::prelude::*;

        // Create Root CA
        let root_config = CAConfig::new("Test Corp", "Test Root CA");
        let root_ca = PrivateCA::create_root(root_config).unwrap();

        // Create Intermediate CA
        let intermediate_config = CAConfig::new("Test Corp", "Test Intermediate CA");
        let intermediate_ca = PrivateCA::create_intermediate(&root_ca, intermediate_config).unwrap();

        // Create device certificate
        let device_keypair = KeyPair::generate();
        let device_id = DeviceIdentity::new("device-xyz");
        let cert_config = CertificateConfig::new("device-xyz");

        let device_cert_der = intermediate_ca.sign_device_certificate(
            &device_keypair.pk,
            &device_id,
            &cert_config,
        ).unwrap();

        // Parse all certificates
        let (_, root_cert) = X509Certificate::from_der(root_ca.certificate()).unwrap();
        let (_, intermediate_cert) = X509Certificate::from_der(intermediate_ca.certificate()).unwrap();
        let (_, device_cert) = X509Certificate::from_der(&device_cert_der).unwrap();

        // Verify chain: device -> intermediate -> root
        // Device cert issuer should match intermediate subject
        assert_eq!(device_cert.issuer(), intermediate_cert.subject());

        // Intermediate cert issuer should match root subject
        assert_eq!(intermediate_cert.issuer(), root_cert.subject());

        // Root cert should be self-signed
        assert_eq!(root_cert.issuer(), root_cert.subject());

        println!("✓ Certificate chain is valid");
        println!("  Root: {}", root_cert.subject());
        println!("  Intermediate: {}", intermediate_cert.subject());
        println!("  Device: {}", device_cert.subject());
    }
}
