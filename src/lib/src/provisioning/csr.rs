/// Certificate Signing Request (CSR) generation
///
/// This module creates X.509 CSRs (PKCS#10) from hardware-backed keys.
/// The CSR is signed by the device's private key (in secure element) and sent
/// to the CA for certificate issuance.

use crate::error::WSError;
use crate::platform::{KeyHandle, SecureKeyProvider};
use crate::provisioning::{CertificateConfig, DeviceIdentity};
use crate::signature::PublicKey;

/// Certificate Signing Request
///
/// Contains device identity and public key, signed by device's private key.
///
/// # Format
///
/// This generates PKCS#10 CSR in DER format:
/// ```text
/// CertificationRequest ::= SEQUENCE {
///   certificationRequestInfo CertificationRequestInfo,
///   signatureAlgorithm AlgorithmIdentifier,
///   signature BIT STRING
/// }
/// ```
pub struct CertificateSigningRequest {
    /// DER-encoded CSR
    der: Vec<u8>,
    /// Device identity
    device_id: DeviceIdentity,
    /// Public key
    public_key: PublicKey,
}

impl CertificateSigningRequest {
    /// Create a new CSR from a hardware key
    ///
    /// # Arguments
    ///
    /// * `provider` - Secure key provider (TPM, Secure Element, etc.)
    /// * `key_handle` - Handle to the device's private key
    /// * `device_id` - Device identity
    /// * `config` - Certificate configuration
    ///
    /// # Security
    ///
    /// The CSR is signed by the device's private key, proving possession of the key.
    /// The private key never leaves the secure hardware.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let device = DeviceIdentity::new("device-123");
    /// let config = CertificateConfig::new("device-123")
    ///     .with_organization("Acme Corp");
    ///
    /// let csr = CertificateSigningRequest::new(
    ///     &provider,
    ///     key_handle,
    ///     device,
    ///     &config
    /// )?;
    /// ```
    pub fn new(
        provider: &dyn SecureKeyProvider,
        key_handle: KeyHandle,
        device_id: DeviceIdentity,
        config: &CertificateConfig,
    ) -> Result<Self, WSError> {
        // Validate device ID
        device_id.validate()?;

        // Get public key from hardware
        let public_key = provider.get_public_key(key_handle)?;

        // Create CSR info (to be signed)
        let csr_info = Self::build_csr_info(&device_id, &public_key, config)?;

        // Sign CSR info with device's private key
        let signature = provider.sign(key_handle, &csr_info)?;

        // Build complete CSR (info + signature)
        let der = Self::build_csr_der(&csr_info, &signature)?;

        Ok(Self {
            der,
            device_id,
            public_key,
        })
    }

    /// Build CSR info structure (to be signed)
    ///
    /// CertificationRequestInfo ::= SEQUENCE {
    ///   version INTEGER { v1(0) },
    ///   subject Name,
    ///   subjectPKInfo SubjectPublicKeyInfo,
    ///   attributes [0] Attributes
    /// }
    fn build_csr_info(
        device_id: &DeviceIdentity,
        public_key: &PublicKey,
        config: &CertificateConfig,
    ) -> Result<Vec<u8>, WSError> {
        use der_encode::*;

        let mut csr_info = Vec::new();

        // Version (v1 = 0)
        csr_info.extend_from_slice(&encode_integer(&[0]));

        // Subject Name
        let subject = Self::build_subject(device_id, config)?;
        csr_info.extend_from_slice(&subject);

        // Subject Public Key Info
        let spki = Self::build_subject_public_key_info(public_key)?;
        csr_info.extend_from_slice(&spki);

        // Attributes (empty for now)
        csr_info.extend_from_slice(&[0xA0, 0x00]); // [0] empty

        // Wrap in SEQUENCE
        Ok(encode_sequence(&csr_info))
    }

    /// Build Subject Name
    ///
    /// Subject ::= SEQUENCE OF RelativeDistinguishedName
    ///
    /// Example:
    /// CN=Device device-123, O=Acme Corp, OU=IoT Devices
    fn build_subject(device_id: &DeviceIdentity, config: &CertificateConfig) -> Result<Vec<u8>, WSError> {
        use der_encode::*;

        let mut rdns = Vec::new();

        // CN (Common Name) = "Device {id}"
        let cn = device_id.to_common_name();
        rdns.push(encode_attribute_type_and_value(&OID_CN, &cn));

        // O (Organization)
        rdns.push(encode_attribute_type_and_value(&OID_O, &config.organization));

        // OU (Organizational Unit) - optional
        if let Some(ou) = &config.organizational_unit {
            rdns.push(encode_attribute_type_and_value(&OID_OU, ou));
        }

        // Wrap in SEQUENCE
        Ok(encode_sequence(&rdns.concat()))
    }

    /// Build Subject Public Key Info
    ///
    /// SubjectPublicKeyInfo ::= SEQUENCE {
    ///   algorithm AlgorithmIdentifier,
    ///   subjectPublicKey BIT STRING
    /// }
    fn build_subject_public_key_info(public_key: &PublicKey) -> Result<Vec<u8>, WSError> {
        // For now, return a placeholder
        // TODO: Implement full SPKI encoding for Ed25519/P-256
        Err(WSError::UnsupportedAlgorithm(
            "CSR generation not yet fully implemented (placeholder)".to_string()
        ))
    }

    /// Build complete CSR DER
    fn build_csr_der(csr_info: &[u8], signature: &[u8]) -> Result<Vec<u8>, WSError> {
        // Placeholder for now
        Err(WSError::UnsupportedAlgorithm(
            "CSR DER building not yet fully implemented (placeholder)".to_string()
        ))
    }

    /// Get DER-encoded CSR
    pub fn to_der(&self) -> &[u8] {
        &self.der
    }

    /// Get PEM-encoded CSR
    pub fn to_pem(&self) -> String {
        use pem::Pem;
        let pem = Pem::new("CERTIFICATE REQUEST", self.der.clone());
        pem::encode(&pem)
    }

    /// Get device identity
    pub fn device_id(&self) -> &DeviceIdentity {
        &self.device_id
    }

    /// Get public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Simple DER encoding helpers
///
/// Note: For production, use a proper ASN.1 library like `der` crate.
/// This is a minimal implementation for demonstration.
mod der_encode {
    // OID for Common Name (CN): 2.5.4.3
    pub const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

    // OID for Organization (O): 2.5.4.10
    pub const OID_O: &[u8] = &[0x55, 0x04, 0x0A];

    // OID for Organizational Unit (OU): 2.5.4.11
    pub const OID_OU: &[u8] = &[0x55, 0x04, 0x0B];

    pub fn encode_integer(value: &[u8]) -> Vec<u8> {
        let mut result = vec![0x02]; // INTEGER tag
        result.push(value.len() as u8);
        result.extend_from_slice(value);
        result
    }

    pub fn encode_sequence(contents: &[u8]) -> Vec<u8> {
        let mut result = vec![0x30]; // SEQUENCE tag
        encode_length(&mut result, contents.len());
        result.extend_from_slice(contents);
        result
    }

    pub fn encode_length(output: &mut Vec<u8>, length: usize) {
        if length < 128 {
            output.push(length as u8);
        } else if length < 256 {
            output.push(0x81);
            output.push(length as u8);
        } else {
            output.push(0x82);
            output.push((length >> 8) as u8);
            output.push((length & 0xFF) as u8);
        }
    }

    pub fn encode_attribute_type_and_value(oid: &[u8], value: &str) -> Vec<u8> {
        let mut attr = Vec::new();

        // OID
        attr.push(0x06); // OBJECT IDENTIFIER tag
        attr.push(oid.len() as u8);
        attr.extend_from_slice(oid);

        // UTF8String value
        attr.push(0x0C); // UTF8String tag
        attr.push(value.len() as u8);
        attr.extend_from_slice(value.as_bytes());

        // Wrap in SEQUENCE
        encode_sequence(&attr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::software::SoftwareProvider;

    #[test]
    fn test_csr_creation_placeholder() {
        // This test will fail until CSR generation is fully implemented
        let provider = SoftwareProvider::new();
        let handle = provider.generate_key().unwrap();
        let device = DeviceIdentity::new("device-123");
        let config = CertificateConfig::new("device-123");

        let result = CertificateSigningRequest::new(
            &provider,
            handle,
            device,
            &config,
        );

        // Expected to fail with UnsupportedAlgorithm for now
        assert!(result.is_err());
    }

    #[test]
    fn test_der_encode_integer() {
        use der_encode::encode_integer;
        let encoded = encode_integer(&[0]);
        assert_eq!(encoded, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_der_encode_sequence() {
        use der_encode::encode_sequence;
        let encoded = encode_sequence(&[0x02, 0x01, 0x00]);
        assert_eq!(encoded, vec![0x30, 0x03, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_der_encode_length_short() {
        use der_encode::encode_length;
        let mut output = Vec::new();
        encode_length(&mut output, 42);
        assert_eq!(output, vec![42]);
    }

    #[test]
    fn test_der_encode_length_medium() {
        use der_encode::encode_length;
        let mut output = Vec::new();
        encode_length(&mut output, 200);
        assert_eq!(output, vec![0x81, 200]);
    }

    #[test]
    fn test_der_encode_length_long() {
        use der_encode::encode_length;
        let mut output = Vec::new();
        encode_length(&mut output, 300);
        assert_eq!(output, vec![0x82, 0x01, 0x2C]); // 300 = 0x012C
    }
}
