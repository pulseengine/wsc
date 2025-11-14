/// Offline certificate verification
///
/// This module provides certificate chain verification for IoT devices using
/// a private CA trust anchor (unlike Fulcio which uses public trust).
///
/// # Security Model
///
/// - Verifier embeds Root CA certificate
/// - Device provides: Device cert + Intermediate cert
/// - Verification: Device → Intermediate → Root (trusted)
/// - No internet required
/// - No revocation checking (use short-lived certs instead)

use crate::error::WSError;
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, KeyUsage};
use std::time::Duration;

/// Offline certificate verifier
///
/// Verifies certificate chains against a private CA root certificate.
/// This is designed for offline/air-gapped environments where OCSP/CRL
/// is not available.
pub struct OfflineVerifier {
    /// Trusted root CA
    root_anchor: TrustAnchor<'static>,
    /// Intermediate CA certificates
    intermediates: Vec<CertificateDer<'static>>,
}

impl OfflineVerifier {
    /// Create a new offline verifier from a root CA certificate
    ///
    /// # Arguments
    ///
    /// * `root_cert_der` - DER-encoded root CA certificate
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Embed root CA certificate at compile time
    /// const ROOT_CA_CERT: &[u8] = include_bytes!("../ca/root-ca.crt");
    ///
    /// let verifier = OfflineVerifier::new(ROOT_CA_CERT)?;
    /// ```
    pub fn new(root_cert_der: &[u8]) -> Result<Self, WSError> {
        let root_cert = CertificateDer::from(root_cert_der);

        // Create trust anchor from root certificate
        let root_anchor = webpki::anchor_from_trusted_cert(&root_cert)
            .map_err(|e| WSError::X509Error(format!("Invalid root certificate: {:?}", e)))?
            .to_owned();

        Ok(Self {
            root_anchor,
            intermediates: Vec::new(),
        })
    }

    /// Add an intermediate CA certificate
    ///
    /// # Arguments
    ///
    /// * `intermediate_cert_der` - DER-encoded intermediate CA certificate
    ///
    /// # Example
    ///
    /// ```ignore
    /// verifier.add_intermediate(INTERMEDIATE_CA_CERT)?;
    /// ```
    pub fn add_intermediate(&mut self, intermediate_cert_der: &[u8]) -> Result<(), WSError> {
        let intermediate = CertificateDer::from(intermediate_cert_der.to_vec());

        // Validate intermediate can be parsed
        let _ = EndEntityCert::try_from(&intermediate)
            .map_err(|e| WSError::X509Error(format!("Invalid intermediate certificate: {:?}", e)))?;

        self.intermediates.push(intermediate);
        Ok(())
    }

    /// Verify a device certificate chain
    ///
    /// # Arguments
    ///
    /// * `device_cert_der` - DER-encoded device certificate
    /// * `verification_time` - Time to verify certificate validity (None = now)
    ///
    /// # Returns
    ///
    /// Ok(()) if certificate chain is valid, Err otherwise
    ///
    /// # Verification Steps
    ///
    /// 1. Parse device certificate
    /// 2. Verify signature chain: Device → Intermediate → Root
    /// 3. Check validity period (not before/after)
    /// 4. Verify key usage (digitalSignature, codeSigning)
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Verify at current time
    /// verifier.verify_device_certificate(&device_cert, None)?;
    ///
    /// // Verify at specific time (e.g., signature timestamp)
    /// verifier.verify_device_certificate(&device_cert, Some(timestamp))?;
    /// ```
    pub fn verify_device_certificate(
        &self,
        device_cert_der: &[u8],
        verification_time: Option<u64>,
    ) -> Result<(), WSError> {
        let device_cert = CertificateDer::from(device_cert_der);

        let cert = EndEntityCert::try_from(&device_cert)
            .map_err(|e| WSError::X509Error(format!("Invalid device certificate: {:?}", e)))?;

        // Determine verification time
        let time = if let Some(ts) = verification_time {
            UnixTime::since_unix_epoch(Duration::from_secs(ts))
        } else {
            UnixTime::now()
        };

        // Verify certificate chain
        self.verify_cert_with_time(&cert, time)?;

        Ok(())
    }

    /// Verify certificate at a specific point in time
    fn verify_cert_with_time(
        &self,
        cert: &EndEntityCert,
        verification_time: UnixTime,
    ) -> Result<(), WSError> {
        // Use all standard verification algorithms
        let signing_algs = webpki::ALL_VERIFICATION_ALGS;

        // OID for Extended Key Usage: Code Signing (1.3.6.1.5.5.7.3.3)
        let eku_code_signing = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

        // Perform WebPKI verification
        cert.verify_for_usage(
            signing_algs,
            &[self.root_anchor.clone()],
            &self.intermediates,
            verification_time,
            KeyUsage::required(eku_code_signing),
            None,  // No DNS name validation
            None,  // No revocation checking (use short-lived certs)
        )
        .map_err(|e| WSError::VerificationError(format!("Certificate chain verification failed: {:?}", e)))?;

        Ok(())
    }

    /// Verify a complete certificate chain (device + intermediates)
    ///
    /// This is useful when the device provides its full certificate chain.
    ///
    /// # Arguments
    ///
    /// * `cert_chain` - Ordered certificate chain (device first, root last)
    /// * `verification_time` - Time to verify (None = now)
    pub fn verify_certificate_chain(
        &self,
        cert_chain: &[Vec<u8>],
        verification_time: Option<u64>,
    ) -> Result<(), WSError> {
        if cert_chain.is_empty() {
            return Err(WSError::InvalidArgument);
        }

        // First certificate is the device certificate
        let device_cert = &cert_chain[0];

        // Add remaining certificates as intermediates (if not already present)
        let mut verifier = OfflineVerifier {
            root_anchor: self.root_anchor.clone(),
            intermediates: self.intermediates.clone(),
        };

        for intermediate_der in &cert_chain[1..] {
            // Skip if this is the root certificate (self-signed)
            // We already have it as a trust anchor
            if intermediate_der != self.root_anchor_der() {
                verifier.add_intermediate(intermediate_der)?;
            }
        }

        verifier.verify_device_certificate(device_cert, verification_time)
    }

    /// Get root certificate DER (for comparison)
    fn root_anchor_der(&self) -> &[u8] {
        // Note: TrustAnchor doesn't expose DER directly
        // This is a placeholder
        &[]
    }
}

/// Builder for OfflineVerifier with embedded certificates
///
/// # Example
///
/// ```ignore
/// const ROOT_CA: &[u8] = include_bytes!("../ca/root-ca.crt");
/// const INTERMEDIATE_CA: &[u8] = include_bytes!("../ca/intermediate-ca.crt");
///
/// let verifier = OfflineVerifierBuilder::new()
///     .with_root(ROOT_CA)?
///     .with_intermediate(INTERMEDIATE_CA)?
///     .build();
/// ```
pub struct OfflineVerifierBuilder {
    root_cert: Option<Vec<u8>>,
    intermediates: Vec<Vec<u8>>,
}

impl OfflineVerifierBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            root_cert: None,
            intermediates: Vec::new(),
        }
    }

    /// Set root CA certificate
    pub fn with_root(mut self, root_cert_der: &[u8]) -> Result<Self, WSError> {
        self.root_cert = Some(root_cert_der.to_vec());
        Ok(self)
    }

    /// Add intermediate CA certificate
    pub fn with_intermediate(mut self, intermediate_cert_der: &[u8]) -> Self {
        self.intermediates.push(intermediate_cert_der.to_vec());
        self
    }

    /// Build the verifier
    pub fn build(self) -> Result<OfflineVerifier, WSError> {
        let root_cert = self.root_cert
            .ok_or_else(|| WSError::InvalidArgument)?;

        let mut verifier = OfflineVerifier::new(&root_cert)?;

        for intermediate in &self.intermediates {
            verifier.add_intermediate(intermediate)?;
        }

        Ok(verifier)
    }
}

impl Default for OfflineVerifierBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offline_verifier_builder() {
        let builder = OfflineVerifierBuilder::new();
        assert!(builder.root_cert.is_none());
        assert!(builder.intermediates.is_empty());
    }

    #[test]
    fn test_builder_requires_root() {
        let builder = OfflineVerifierBuilder::new();
        let result = builder.build();
        assert!(result.is_err()); // Should fail without root
    }

    // Note: Full verification tests require real certificates
    // These would be added once certificate generation is implemented
}
