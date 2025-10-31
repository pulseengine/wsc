//! Certificate chain verification for Fulcio certificates
//!
//! This module implements X.509 certificate chain validation using rustls-webpki.
//! It verifies that certificates issued by Fulcio:
//! 1. Chain up to a trusted Fulcio root CA
//! 2. Have valid signatures at each level
//! 3. Were valid at the time of signing (integrated_time from Rekor)
//! 4. Have the correct key usages (digitalSignature, codeSigning)
//!
//! # Security Model
//!
//! Trust anchors (Fulcio root CAs) are embedded from Sigstore's TUF repository.
//! The verification process follows RFC 5280 and WebPKI best practices.

use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, KeyUsage};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use base64::prelude::*;

/// Errors that can occur during certificate verification
#[derive(Debug, Error)]
pub enum CertVerificationError {
    #[error("Failed to parse certificate: {0}")]
    ParseError(String),

    #[error("Certificate chain verification failed: {0}")]
    ChainVerificationFailed(String),

    #[error("Certificate is not yet valid (not before: {0})")]
    NotYetValid(String),

    #[error("Certificate expired before signature was created (not after: {0}, signature time: {1})")]
    ExpiredBeforeSignature(String, String),

    #[error("Failed to parse PEM: {0}")]
    PemParseError(String),

    #[error("No trusted root CA found")]
    NoTrustedRoot,

    #[error("Invalid JSON in trusted_root.json: {0}")]
    InvalidTrustedRootJson(String),

    #[error("Certificate missing required extension: {0}")]
    MissingExtension(String),

    #[error("Invalid key usage")]
    InvalidKeyUsage,
}

/// Trusted root configuration from Sigstore TUF
#[derive(Debug, Serialize, Deserialize)]
pub struct TrustedRoot {
    #[serde(rename = "certificateAuthorities")]
    pub certificate_authorities: Vec<CertificateAuthority>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateAuthority {
    pub subject: Subject,
    pub uri: String,
    #[serde(rename = "certChain")]
    pub cert_chain: CertChain,
    #[serde(rename = "validFor")]
    pub valid_for: ValidFor,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Subject {
    pub organization: String,
    #[serde(rename = "commonName")]
    pub common_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertChain {
    pub certificates: Vec<CertificateEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateEntry {
    #[serde(rename = "rawBytes")]
    pub raw_bytes: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidFor {
    pub start: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
}

/// A pool of trusted root and intermediate certificates for verification
pub struct CertificatePool {
    trusted_roots: Vec<TrustAnchor<'static>>,
    intermediates: Vec<CertificateDer<'static>>,
}

impl CertificatePool {
    /// Load the default Fulcio trusted roots from embedded trusted_root.json
    pub fn from_embedded_trust_root() -> Result<Self, CertVerificationError> {
        // Load embedded trusted_root.json
        let trusted_root_json = include_str!("trust_root/trusted_root.json");

        let trusted_root: TrustedRoot = serde_json::from_str(trusted_root_json)
            .map_err(|e| CertVerificationError::InvalidTrustedRootJson(e.to_string()))?;

        Self::from_trusted_root(trusted_root)
    }

    /// Create a certificate pool from a TrustedRoot structure
    pub fn from_trusted_root(trusted_root: TrustedRoot) -> Result<Self, CertVerificationError> {
        let mut trusted_roots = Vec::new();
        let mut all_intermediates = Vec::new();

        for ca in trusted_root.certificate_authorities {
            let certs = ca.cert_chain.certificates;

            if certs.is_empty() {
                continue;
            }

            // Decode all certificates in the chain
            let mut decoded_certs = Vec::new();
            for cert_entry in &certs {
                let der = base64::prelude::BASE64_STANDARD.decode(&cert_entry.raw_bytes)
                    .map_err(|e| CertVerificationError::ParseError(format!("Base64 decode failed: {}", e)))?;
                decoded_certs.push(CertificateDer::from(der));
            }

            // Last certificate in chain is the root (self-signed)
            // Earlier certificates are intermediates
            if decoded_certs.len() == 1 {
                // Single cert - treat as root
                let root_cert = &decoded_certs[0];
                let trust_anchor = webpki::anchor_from_trusted_cert(root_cert)
                    .map_err(|e| CertVerificationError::ParseError(format!("Failed to create trust anchor: {:?}", e)))?
                    .to_owned();
                trusted_roots.push(trust_anchor);
            } else {
                // Multiple certs - last is root, others are intermediates
                let root_cert = &decoded_certs[decoded_certs.len() - 1];
                let trust_anchor = webpki::anchor_from_trusted_cert(root_cert)
                    .map_err(|e| CertVerificationError::ParseError(format!("Failed to create trust anchor: {:?}", e)))?
                    .to_owned();
                trusted_roots.push(trust_anchor);

                // Add intermediates
                for intermediate in &decoded_certs[0..decoded_certs.len() - 1] {
                    all_intermediates.push(intermediate.clone().into_owned());
                }
            }
        }

        if trusted_roots.is_empty() {
            return Err(CertVerificationError::NoTrustedRoot);
        }

        Ok(Self {
            trusted_roots,
            intermediates: all_intermediates,
        })
    }

    /// Verify a certificate chain from a PEM-encoded certificate
    ///
    /// # Arguments
    /// * `cert_pem` - PEM-encoded certificate (leaf certificate)
    /// * `integrated_time` - Unix timestamp when signature was created (from Rekor)
    ///
    /// # Security
    /// This performs full RFC 5280 path validation including:
    /// - Signature verification at each level
    /// - Validity period checking
    /// - Key usage validation
    /// - Chain building up to trusted root
    pub fn verify_pem_cert(
        &self,
        cert_pem: &[u8],
        integrated_time: i64,
    ) -> Result<(), CertVerificationError> {
        // Parse PEM
        let pem = pem::parse(cert_pem)
            .map_err(|e| CertVerificationError::PemParseError(e.to_string()))?;

        if pem.tag() != "CERTIFICATE" {
            return Err(CertVerificationError::PemParseError(
                "PEM file is not a CERTIFICATE".to_string(),
            ));
        }

        self.verify_der_cert(pem.contents(), integrated_time)
    }

    /// Verify a certificate chain from DER-encoded certificate
    pub fn verify_der_cert(
        &self,
        cert_der: &[u8],
        integrated_time: i64,
    ) -> Result<(), CertVerificationError> {
        let cert_der = CertificateDer::from(cert_der);
        let cert = EndEntityCert::try_from(&cert_der)
            .map_err(|e| CertVerificationError::ParseError(format!("Failed to parse certificate: {:?}", e)))?;

        // Convert integrated_time to UnixTime for verification
        let verification_time = UnixTime::since_unix_epoch(Duration::from_secs(integrated_time as u64));

        self.verify_cert_with_time(&cert, verification_time)
    }

    /// Verify certificate at a specific point in time
    fn verify_cert_with_time(
        &self,
        cert: &EndEntityCert,
        verification_time: UnixTime,
    ) -> Result<(), CertVerificationError> {
        // Use all standard verification algorithms
        let signing_algs = webpki::ALL_VERIFICATION_ALGS;

        // OID for Extended Key Usage: Code Signing (1.3.6.1.5.5.7.3.3)
        // This is required for Fulcio certificates
        let eku_code_signing = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

        // Perform WebPKI verification
        // This checks:
        // 1. Certificate signatures (crypto verification)
        // 2. Chain building to trusted root
        // 3. Validity periods
        // 4. Key usage and extended key usage
        cert.verify_for_usage(
            signing_algs,
            &self.trusted_roots,
            &self.intermediates,
            verification_time,
            KeyUsage::required(eku_code_signing),
            None,  // No DNS name validation needed
            None,  // No revocation checking yet (TODO: Issue #2)
        )
        .map_err(|e| CertVerificationError::ChainVerificationFailed(format!("{:?}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_embedded_trust_root() {
        let pool = CertificatePool::from_embedded_trust_root();
        assert!(pool.is_ok(), "Failed to load embedded trust root: {:?}", pool.err());

        let pool = pool.unwrap();
        assert!(!pool.trusted_roots.is_empty(), "No trusted roots loaded");

        println!("Loaded {} trusted roots", pool.trusted_roots.len());
        println!("Loaded {} intermediates", pool.intermediates.len());
    }

    #[test]
    fn test_trusted_root_json_structure() {
        let trusted_root_json = include_str!("trust_root/trusted_root.json");
        let result: Result<TrustedRoot, _> = serde_json::from_str(trusted_root_json);

        assert!(result.is_ok(), "Failed to parse trusted_root.json: {:?}", result.err());

        let trusted_root = result.unwrap();
        assert!(!trusted_root.certificate_authorities.is_empty(), "No certificate authorities found");

        for ca in &trusted_root.certificate_authorities {
            println!("CA: {} - {}", ca.subject.organization, ca.subject.common_name);
            println!("  URI: {}", ca.uri);
            println!("  Certificates: {}", ca.cert_chain.certificates.len());
        }
    }
}
