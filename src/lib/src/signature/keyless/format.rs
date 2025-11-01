use crate::error::WSError;
use crate::wasm_module::varint;
use serde_json;
use std::io::{Cursor, Write};
use x509_parser::prelude::*;

// Re-export RekorEntry from the rekor module
pub use super::rekor::RekorEntry;
use super::cert_verifier::CertificatePool;

/// Binary format version for keyless signatures
pub const KEYLESS_VERSION: u8 = 0x02;

/// Signature type identifier for keyless signatures
pub const KEYLESS_SIG_TYPE: u8 = 0x02;

/// Standard signature type identifier
pub const STANDARD_SIG_TYPE: u8 = 0x01;

/// Keyless signature custom section format
///
/// Binary format (extends existing wasmsig format):
/// ```text
/// [version: u8 = 0x02]              // New version for keyless
/// [sig_type: u8 = 0x02]             // 0x01 = standard, 0x02 = keyless
/// [signature_len: varint]
/// [signature: bytes]
/// [cert_chain_count: u8]
/// [cert_1_len: varint]
/// [cert_1: bytes]
/// ...
/// [rekor_entry_len: varint]
/// [rekor_entry: JSON bytes]
/// [module_hash_len: varint]
/// [module_hash: bytes]
/// ```
#[derive(Debug, Clone)]
pub struct KeylessSignature {
    /// Ed25519 signature over the module hash
    pub signature: Vec<u8>,
    /// X.509 certificate chain from Fulcio (PEM format)
    pub cert_chain: Vec<String>,
    /// Rekor transparency log entry
    pub rekor_entry: RekorEntry,
    /// SHA256 hash of the WASM module that was signed
    pub module_hash: Vec<u8>,
}

impl KeylessSignature {
    /// Create a new keyless signature
    pub fn new(
        signature: Vec<u8>,
        cert_chain: Vec<String>,
        rekor_entry: RekorEntry,
        module_hash: Vec<u8>,
    ) -> Self {
        Self {
            signature,
            cert_chain,
            rekor_entry,
            module_hash,
        }
    }

    /// Serialize to bytes for WASM custom section
    ///
    /// # Binary Format
    ///
    /// The serialized format is:
    /// - Version byte (0x02)
    /// - Signature type byte (0x02 for keyless)
    /// - Signature length (varint) + signature bytes
    /// - Certificate chain count (u8)
    /// - For each certificate: length (varint) + PEM bytes
    /// - Rekor entry length (varint) + JSON bytes
    /// - Module hash length (varint) + hash bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, WSError> {
        let mut buffer = Vec::new();

        // Write version
        buffer.write_all(&[KEYLESS_VERSION]).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write version: {}", e))
        })?;

        // Write signature type
        buffer.write_all(&[KEYLESS_SIG_TYPE]).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write signature type: {}", e))
        })?;

        // Write signature
        varint::put_slice(&mut buffer, &self.signature).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write signature: {}", e))
        })?;

        // Write certificate chain count
        let cert_count = self.cert_chain.len();
        if cert_count > 255 {
            return Err(WSError::KeylessFormatError(format!(
                "Certificate chain too long: {} (max 255)",
                cert_count
            )));
        }
        buffer
            .write_all(&[cert_count as u8])
            .map_err(|e| WSError::KeylessFormatError(format!("Failed to write cert count: {}", e)))?;

        // Write each certificate
        for (i, cert_pem) in self.cert_chain.iter().enumerate() {
            varint::put_slice(&mut buffer, cert_pem.as_bytes()).map_err(|e| {
                WSError::KeylessFormatError(format!("Failed to write certificate {}: {}", i, e))
            })?;
        }

        // Serialize Rekor entry to JSON
        let rekor_json = serde_json::to_vec(&self.rekor_entry).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to serialize Rekor entry: {}", e))
        })?;

        // Write Rekor entry
        varint::put_slice(&mut buffer, &rekor_json).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write Rekor entry: {}", e))
        })?;

        // Write module hash
        varint::put_slice(&mut buffer, &self.module_hash).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write module hash: {}", e))
        })?;

        Ok(buffer)
    }

    /// Deserialize from WASM custom section bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw bytes from the WASM custom section
    ///
    /// # Returns
    ///
    /// A parsed `KeylessSignature` or an error if the format is invalid
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WSError> {
        let mut reader = Cursor::new(bytes);

        // Read and verify version
        let mut version = [0u8; 1];
        std::io::Read::read_exact(&mut reader, &mut version).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to read version: {}", e))
        })?;
        if version[0] != KEYLESS_VERSION {
            return Err(WSError::KeylessFormatError(format!(
                "Unsupported version: {} (expected {})",
                version[0], KEYLESS_VERSION
            )));
        }

        // Read and verify signature type
        let mut sig_type = [0u8; 1];
        std::io::Read::read_exact(&mut reader, &mut sig_type).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to read signature type: {}", e))
        })?;
        if sig_type[0] != KEYLESS_SIG_TYPE {
            return Err(WSError::KeylessFormatError(format!(
                "Unsupported signature type: {} (expected {})",
                sig_type[0], KEYLESS_SIG_TYPE
            )));
        }

        // Read signature
        let signature = varint::get_slice(&mut reader).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to read signature: {}", e))
        })?;

        // Read certificate chain count
        let mut cert_count = [0u8; 1];
        std::io::Read::read_exact(&mut reader, &mut cert_count).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to read certificate count: {}", e))
        })?;

        // Read certificates
        let mut cert_chain = Vec::new();
        for i in 0..cert_count[0] {
            let cert_bytes = varint::get_slice(&mut reader).map_err(|e| {
                WSError::KeylessFormatError(format!("Failed to read certificate {}: {}", i, e))
            })?;
            let cert_pem = String::from_utf8(cert_bytes).map_err(|e| {
                WSError::KeylessFormatError(format!(
                    "Certificate {} is not valid UTF-8: {}",
                    i, e
                ))
            })?;
            cert_chain.push(cert_pem);
        }

        // Read Rekor entry
        let rekor_json = varint::get_slice(&mut reader).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to read Rekor entry: {}", e))
        })?;
        let rekor_entry: RekorEntry = serde_json::from_slice(&rekor_json).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to parse Rekor entry JSON: {}", e))
        })?;

        // Read module hash
        let module_hash = varint::get_slice(&mut reader).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to read module hash: {}", e))
        })?;

        Ok(Self {
            signature,
            cert_chain,
            rekor_entry,
            module_hash,
        })
    }

    /// Extract identity from the leaf certificate
    ///
    /// The identity is typically stored in the Subject Alternative Name (SAN) extension,
    /// which contains the email, URI, or other identity from the OIDC token.
    ///
    /// # Returns
    ///
    /// The identity string (e.g., "user@example.com", "https://github.com/user/repo")
    pub fn get_identity(&self) -> Result<String, WSError> {
        if self.cert_chain.is_empty() {
            return Err(WSError::CertificateError(
                "No certificates in chain".to_string(),
            ));
        }

        // Parse the leaf certificate (first in chain)
        let leaf_pem = &self.cert_chain[0];
        let (_, pem) = parse_x509_pem(leaf_pem.as_bytes()).map_err(|e| {
            WSError::CertificateError(format!("Failed to parse PEM: {}", e))
        })?;

        let cert = pem.parse_x509().map_err(|e| {
            WSError::CertificateError(format!("Failed to parse X.509 certificate: {}", e))
        })?;

        // Look for Subject Alternative Name extension
        if let Some(san_ext) = cert.get_extension_unique(&oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)? {
            if let ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() {
                // Try different SAN types in order of preference
                for name in &san.general_names {
                    match name {
                        GeneralName::RFC822Name(email) => {
                            return Ok(email.to_string());
                        }
                        GeneralName::URI(uri) => {
                            return Ok(uri.to_string());
                        }
                        GeneralName::DNSName(dns) => {
                            return Ok(dns.to_string());
                        }
                        _ => continue,
                    }
                }
            }
        }

        // Fall back to subject common name if no SAN found
        for rdn in cert.subject().iter() {
            for attr in rdn.iter() {
                if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME {
                    if let Ok(cn) = attr.as_str() {
                        return Ok(cn.to_string());
                    }
                }
            }
        }

        Err(WSError::CertificateError(
            "No identity found in certificate".to_string(),
        ))
    }

    /// Extract issuer from the leaf certificate
    ///
    /// The issuer identifies the OIDC provider that issued the identity token
    /// (e.g., "https://accounts.google.com", "https://token.actions.githubusercontent.com").
    ///
    /// For Fulcio certificates, this is stored in a custom OID extension.
    ///
    /// # Returns
    ///
    /// The issuer URL string
    pub fn get_issuer(&self) -> Result<String, WSError> {
        if self.cert_chain.is_empty() {
            return Err(WSError::CertificateError(
                "No certificates in chain".to_string(),
            ));
        }

        // Parse the leaf certificate (first in chain)
        let leaf_pem = &self.cert_chain[0];
        let (_, pem) = parse_x509_pem(leaf_pem.as_bytes()).map_err(|e| {
            WSError::CertificateError(format!("Failed to parse PEM: {}", e))
        })?;

        let cert = pem.parse_x509().map_err(|e| {
            WSError::CertificateError(format!("Failed to parse X.509 certificate: {}", e))
        })?;

        // Sigstore uses custom OID 1.3.6.1.4.1.57264.1.1 for the OIDC issuer
        // For now, we'll parse the issuer from the certificate issuer field
        // TODO: Parse custom Sigstore OID when x509-parser supports custom OIDs

        // Extract issuer common name as a fallback
        for rdn in cert.issuer().iter() {
            for attr in rdn.iter() {
                if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME {
                    if let Ok(cn) = attr.as_str() {
                        return Ok(cn.to_string());
                    }
                }
            }
        }

        Err(WSError::CertificateError(
            "No issuer found in certificate".to_string(),
        ))
    }

    /// Verify the certificate chain
    ///
    /// This performs full RFC 5280 certificate chain validation:
    /// - Validates certificate chain up to Fulcio root CA
    /// - Checks certificate signatures at each level
    /// - Verifies validity periods match Rekor integrated_time
    /// - Validates certificate extensions (Key Usage, Extended Key Usage)
    ///
    /// # Returns
    ///
    /// Ok if the certificate chain is valid, error otherwise
    ///
    /// # Security
    ///
    /// Uses WebPKI (rustls-webpki) for cryptographic verification.
    /// Trust anchors are embedded from Sigstore TUF repository.
    pub fn verify_cert_chain(&self) -> Result<(), WSError> {
        if self.cert_chain.is_empty() {
            return Err(WSError::CertificateError(
                "Empty certificate chain".to_string(),
            ));
        }

        // Load Fulcio trusted roots
        let cert_pool = CertificatePool::from_embedded_trust_root()
            .map_err(|e| WSError::CertificateError(format!("Failed to load trusted roots: {}", e)))?;

        // Parse integrated_time from Rekor entry (RFC3339 format)
        let integrated_time = chrono::DateTime::parse_from_rfc3339(&self.rekor_entry.integrated_time)
            .map_err(|e| WSError::CertificateError(format!("Failed to parse integrated_time: {}", e)))?;

        let integrated_time_unix = integrated_time.timestamp();

        // Verify the leaf certificate (first in chain)
        // The leaf certificate must chain up to a trusted Fulcio root CA
        let leaf_cert_pem = self.cert_chain.first()
            .ok_or_else(|| WSError::CertificateError("No leaf certificate in chain".to_string()))?;

        cert_pool.verify_pem_cert(leaf_cert_pem.as_bytes(), integrated_time_unix)
            .map_err(|e| WSError::CertificateError(format!("Certificate verification failed: {}", e)))?;

        log::debug!("Certificate chain verified successfully");
        Ok(())
    }

    /// Verify the Rekor inclusion proof
    ///
    /// This is a stub implementation that always returns Ok.
    /// Full implementation will:
    /// - Verify the Merkle tree inclusion proof
    /// - Check the signed entry timestamp
    /// - Validate against Rekor's public key
    /// - Ensure timestamp is within certificate validity period
    ///
    /// # Returns
    ///
    /// Ok if the inclusion proof is valid, error otherwise
    pub fn verify_rekor_inclusion(&self) -> Result<(), WSError> {
        // Stub: Always return Ok for now
        // TODO: Implement full Rekor inclusion proof verification
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_signature() -> KeylessSignature {
        let signature = vec![1, 2, 3, 4, 5];
        let cert_chain = vec![
            "-----BEGIN CERTIFICATE-----\ntest cert 1\n-----END CERTIFICATE-----".to_string(),
            "-----BEGIN CERTIFICATE-----\ntest cert 2\n-----END CERTIFICATE-----".to_string(),
        ];
        let rekor_entry = RekorEntry {
            uuid: "test-uuid-1234".to_string(),
            log_index: 42,
            body: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            log_id: "test-log-id".to_string(),
            inclusion_proof: vec![10, 20, 30, 40],
            signed_entry_timestamp: "c2lnbmF0dXJl".to_string(),
            integrated_time: "2024-01-01T00:00:00Z".to_string(),
        };
        let module_hash = vec![0xde, 0xad, 0xbe, 0xef];

        KeylessSignature::new(signature, cert_chain, rekor_entry, module_hash)
    }

    #[test]
    fn test_serialization_roundtrip() {
        let sig = create_test_signature();

        // Serialize to bytes
        let bytes = sig.to_bytes().expect("Serialization failed");

        // Verify format markers
        assert_eq!(bytes[0], KEYLESS_VERSION);
        assert_eq!(bytes[1], KEYLESS_SIG_TYPE);

        // Deserialize back
        let deserialized = KeylessSignature::from_bytes(&bytes).expect("Deserialization failed");

        // Verify all fields match
        assert_eq!(deserialized.signature, sig.signature);
        assert_eq!(deserialized.cert_chain, sig.cert_chain);
        assert_eq!(deserialized.rekor_entry.uuid, sig.rekor_entry.uuid);
        assert_eq!(deserialized.rekor_entry.log_index, sig.rekor_entry.log_index);
        assert_eq!(
            deserialized.rekor_entry.inclusion_proof,
            sig.rekor_entry.inclusion_proof
        );
        assert_eq!(
            deserialized.rekor_entry.integrated_time,
            sig.rekor_entry.integrated_time
        );
        assert_eq!(deserialized.module_hash, sig.module_hash);
    }

    #[test]
    fn test_empty_cert_chain() {
        let mut sig = create_test_signature();
        sig.cert_chain = vec![];

        let bytes = sig.to_bytes().expect("Serialization should succeed");
        let deserialized =
            KeylessSignature::from_bytes(&bytes).expect("Deserialization should succeed");

        assert_eq!(deserialized.cert_chain.len(), 0);
    }

    #[test]
    fn test_single_cert_chain() {
        let mut sig = create_test_signature();
        sig.cert_chain = vec!["-----BEGIN CERTIFICATE-----\nsingle\n-----END CERTIFICATE-----"
            .to_string()];

        let bytes = sig.to_bytes().expect("Serialization should succeed");
        let deserialized =
            KeylessSignature::from_bytes(&bytes).expect("Deserialization should succeed");

        assert_eq!(deserialized.cert_chain.len(), 1);
        assert_eq!(deserialized.cert_chain[0], sig.cert_chain[0]);
    }

    #[test]
    fn test_max_cert_chain() {
        let mut sig = create_test_signature();
        // Create 255 certificates (max allowed)
        sig.cert_chain = (0..255)
            .map(|i| format!("-----BEGIN CERTIFICATE-----\ncert {}\n-----END CERTIFICATE-----", i))
            .collect();

        let bytes = sig.to_bytes().expect("Serialization should succeed");
        let deserialized =
            KeylessSignature::from_bytes(&bytes).expect("Deserialization should succeed");

        assert_eq!(deserialized.cert_chain.len(), 255);
    }

    #[test]
    fn test_too_many_certs() {
        let mut sig = create_test_signature();
        // Create 256 certificates (one too many)
        sig.cert_chain = (0..256)
            .map(|i| format!("-----BEGIN CERTIFICATE-----\ncert {}\n-----END CERTIFICATE-----", i))
            .collect();

        let result = sig.to_bytes();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::KeylessFormatError(_)));
    }

    #[test]
    fn test_invalid_version() {
        let sig = create_test_signature();
        let mut bytes = sig.to_bytes().expect("Serialization failed");

        // Corrupt version byte
        bytes[0] = 0xFF;

        let result = KeylessSignature::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::KeylessFormatError(_)));
    }

    #[test]
    fn test_invalid_signature_type() {
        let sig = create_test_signature();
        let mut bytes = sig.to_bytes().expect("Serialization failed");

        // Corrupt signature type byte
        bytes[1] = STANDARD_SIG_TYPE;

        let result = KeylessSignature::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::KeylessFormatError(_)));
    }

    #[test]
    fn test_truncated_data() {
        let sig = create_test_signature();
        let bytes = sig.to_bytes().expect("Serialization failed");

        // Try to deserialize truncated data
        let truncated = &bytes[0..5];
        let result = KeylessSignature::from_bytes(truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_rekor_entry_json_serialization() {
        let entry = RekorEntry {
            uuid: "test-uuid".to_string(),
            log_index: 123,
            body: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            log_id: "test-log-id".to_string(),
            inclusion_proof: vec![1, 2, 3],
            signed_entry_timestamp: "c2lnbmF0dXJl".to_string(),
            integrated_time: "2024-01-01T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&entry).expect("JSON serialization failed");
        let deserialized: RekorEntry =
            serde_json::from_str(&json).expect("JSON deserialization failed");

        assert_eq!(deserialized.uuid, entry.uuid);
        assert_eq!(deserialized.log_index, entry.log_index);
        assert_eq!(deserialized.body, entry.body);
        assert_eq!(deserialized.log_id, entry.log_id);
        assert_eq!(deserialized.inclusion_proof, entry.inclusion_proof);
        assert_eq!(deserialized.signed_entry_timestamp, entry.signed_entry_timestamp);
        assert_eq!(deserialized.integrated_time, entry.integrated_time);
    }

    #[test]
    fn test_verify_cert_chain_rejects_invalid() {
        let sig = create_test_signature();
        // Real implementation should reject fake test certificates
        // (create_test_signature uses dummy PEM data, not real Fulcio certs)
        assert!(sig.verify_cert_chain().is_err());

        // Empty chain should also be rejected
        let mut empty_sig = sig.clone();
        empty_sig.cert_chain = vec![];
        assert!(empty_sig.verify_cert_chain().is_err());
    }

    #[test]
    fn test_verify_rekor_inclusion_stub() {
        let sig = create_test_signature();
        // Stub implementation should always return Ok
        assert!(sig.verify_rekor_inclusion().is_ok());
    }

    #[test]
    fn test_get_identity_no_certs() {
        let mut sig = create_test_signature();
        sig.cert_chain = vec![];

        let result = sig.get_identity();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::CertificateError(_)));
    }

    #[test]
    fn test_get_issuer_no_certs() {
        let mut sig = create_test_signature();
        sig.cert_chain = vec![];

        let result = sig.get_issuer();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::CertificateError(_)));
    }

    #[test]
    fn test_large_signature() {
        let mut sig = create_test_signature();
        // Create a large signature (64 bytes, typical for Ed25519)
        sig.signature = vec![0x42; 64];

        let bytes = sig.to_bytes().expect("Serialization failed");
        let deserialized = KeylessSignature::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(deserialized.signature.len(), 64);
        assert_eq!(deserialized.signature, sig.signature);
    }

    #[test]
    fn test_large_module_hash() {
        let mut sig = create_test_signature();
        // Create a SHA-256 hash (32 bytes)
        sig.module_hash = vec![0xFF; 32];

        let bytes = sig.to_bytes().expect("Serialization failed");
        let deserialized = KeylessSignature::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(deserialized.module_hash.len(), 32);
        assert_eq!(deserialized.module_hash, sig.module_hash);
    }
}
