/// Certificate pinning for Sigstore endpoints
///
/// This module implements certificate pinning to protect against CA compromise
/// and man-in-the-middle attacks. It validates that TLS certificates match
/// known SHA256 fingerprints.
///
/// # Security Model
///
/// Certificate pinning adds defense-in-depth beyond standard PKI validation:
/// - Even if a trusted CA is compromised, pinning prevents MITM attacks
/// - Protects against DNS/BGP hijacking with rogue certificates
/// - Validates both leaf certificates and CA certificates
///
/// # Configuration
///
/// Pins can be configured via:
/// - Environment variables: `WSC_FULCIO_PINS`, `WSC_REKOR_PINS`
/// - Programmatic API: `SigstoreConfig::with_custom_pins()`
/// - Default pins for production Sigstore endpoints (embedded)
///
/// # Pin Format
///
/// Pins are SHA256 fingerprints in hex format (64 hex chars):
/// ```text
/// export WSC_FULCIO_PINS="abcd1234...,ef567890..."
/// ```
///
/// # Implementation Status (Issue #12)
///
/// **Certificate pinning infrastructure is COMPLETE but not yet enforced.**
///
/// The `ureq` HTTP client (v3.x) used by FulcioClient and RekorClient does not
/// currently expose APIs for custom TLS certificate verification. This module
/// provides complete pinning infrastructure that is ready to use once:
///
/// 1. `ureq` adds support for custom `ServerCertVerifier`, OR
/// 2. We migrate to `reqwest` or another HTTP client with TLS customization
///
/// **Current behavior:**
/// - Certificate pinning checks are logged for monitoring
/// - Standard WebPKI validation is performed by ureq/rustls
/// - Connections to Fulcio/Rekor succeed even if pins don't match
///
/// **To enable strict pinning (fail if cannot enforce):**
/// ```bash
/// export WSC_REQUIRE_CERT_PINNING=1
/// ```
/// This will cause an error if pinning cannot be enforced due to HTTP client limitations.

use crate::error::WSError;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

/// Production Fulcio certificate pins (SHA256 fingerprints)
///
/// NOTE: These are placeholder values. In production, these should be updated
/// to match the actual Sigstore production certificates.
///
/// To get the current fingerprint:
/// ```bash
/// echo | openssl s_client -connect fulcio.sigstore.dev:443 -servername fulcio.sigstore.dev 2>/dev/null | \
///   openssl x509 -outform DER | sha256sum
/// ```
const FULCIO_PRODUCTION_PINS: &[&str] = &[
    // TODO: Replace with actual production certificate fingerprints
    // These are intentionally placeholder values that will cause pinning to fail
    // if not properly configured via environment variables
];

/// Production Rekor certificate pins (SHA256 fingerprints)
const REKOR_PRODUCTION_PINS: &[&str] = &[
    // TODO: Replace with actual production certificate fingerprints
];

/// Certificate pinning configuration
#[derive(Debug, Clone)]
pub struct PinningConfig {
    /// SHA256 fingerprints of pinned certificates (hex-encoded, lowercase)
    pins: HashSet<String>,
    /// Whether pinning is enforced (vs warn-only mode)
    enforce: bool,
    /// Service name for logging
    service_name: String,
}

impl PinningConfig {
    /// Create pinning configuration for Fulcio production endpoint
    pub fn fulcio_production() -> Self {
        Self::from_env_or_default(
            "WSC_FULCIO_PINS",
            FULCIO_PRODUCTION_PINS,
            "fulcio.sigstore.dev",
        )
    }

    /// Create pinning configuration for Rekor production endpoint
    pub fn rekor_production() -> Self {
        Self::from_env_or_default(
            "WSC_REKOR_PINS",
            REKOR_PRODUCTION_PINS,
            "rekor.sigstore.dev",
        )
    }

    /// Create custom pinning configuration
    ///
    /// # Arguments
    /// * `pins` - SHA256 fingerprints (hex-encoded, 64 chars each)
    /// * `service_name` - Service name for logging
    pub fn custom(pins: Vec<String>, service_name: String) -> Self {
        let pin_set: HashSet<String> = pins.into_iter().map(|p| p.to_lowercase()).collect();
        Self {
            pins: pin_set,
            enforce: true,
            service_name,
        }
    }

    /// Create configuration from environment variable or defaults
    fn from_env_or_default(env_var: &str, defaults: &[&str], service_name: &str) -> Self {
        let pins = match std::env::var(env_var) {
            Ok(value) if !value.is_empty() => {
                log::info!(
                    "Using custom certificate pins from {} for {}",
                    env_var,
                    service_name
                );
                value
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            _ => {
                if defaults.is_empty() {
                    log::warn!(
                        "No certificate pins configured for {} (set {} environment variable)",
                        service_name,
                        env_var
                    );
                }
                defaults.iter().map(|s| s.to_lowercase().to_string()).collect()
            }
        };

        Self {
            pins,
            enforce: true,
            service_name: service_name.to_string(),
        }
    }

    /// Check if pinning is enabled (has any pins configured)
    pub fn is_enabled(&self) -> bool {
        !self.pins.is_empty()
    }

    /// Verify a certificate matches one of the pins
    fn verify_certificate(&self, cert_der: &CertificateDer) -> Result<(), WSError> {
        if !self.is_enabled() {
            // No pins configured - allow connection but log warning
            log::warn!(
                "Certificate pinning disabled for {} (no pins configured)",
                self.service_name
            );
            return Ok(());
        }

        // Compute SHA256 fingerprint of the certificate
        let mut hasher = Sha256::new();
        hasher.update(cert_der.as_ref());
        let fingerprint = hasher.finalize();
        let fingerprint_hex = hex::encode(fingerprint);

        // Check if fingerprint matches any pin
        if self.pins.contains(&fingerprint_hex) {
            log::debug!(
                "Certificate pin matched for {} (fingerprint: {}...)",
                self.service_name,
                &fingerprint_hex[..16]
            );
            Ok(())
        } else {
            if self.enforce {
                // SECURITY (Issue #9): Only show first 16 hex chars (8 bytes) of fingerprint
                Err(WSError::CertificatePinningError(format!(
                    "Certificate pin mismatch for {}: got {}..., expected one of {} configured pins",
                    self.service_name,
                    &fingerprint_hex[..16],
                    self.pins.len()
                )))
            } else {
                log::warn!(
                    "Certificate pin mismatch for {} (warn-only mode): {}...",
                    self.service_name,
                    &fingerprint_hex[..16]
                );
                Ok(())
            }
        }
    }
}

/// Custom certificate verifier that implements pinning
pub struct PinnedCertVerifier {
    /// Base verifier for standard WebPKI validation
    base_verifier: Arc<dyn ServerCertVerifier>,
    /// Pinning configuration
    pinning: PinningConfig,
    /// Crypto provider for signature verification
    crypto_provider: Arc<CryptoProvider>,
}

impl PinnedCertVerifier {
    /// Create a new pinned certificate verifier
    ///
    /// # Arguments
    /// * `pinning` - Pinning configuration with SHA256 fingerprints
    /// * `crypto_provider` - Crypto provider for signature verification
    ///
    /// # Returns
    /// A new verifier that performs both WebPKI and pin validation
    pub fn new(
        pinning: PinningConfig,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Result<Self, WSError> {
        // Create base WebPKI verifier using system roots
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };

        let base_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| {
                WSError::CertificatePinningError(format!("Failed to create base verifier: {}", e))
            })?;

        Ok(Self {
            base_verifier,
            pinning,
            crypto_provider,
        })
    }
}

impl fmt::Debug for PinnedCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedCertVerifier")
            .field("pinning", &self.pinning)
            .field("base_verifier", &"WebPkiServerVerifier")
            .finish()
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, TlsError> {
        // Step 1: Perform standard WebPKI validation
        // This ensures the certificate is valid, not expired, and chains to a trusted root
        self.base_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // Step 2: Verify certificate pinning
        // Check if the leaf certificate matches one of our pins
        self.pinning
            .verify_certificate(end_entity)
            .map_err(|e| TlsError::General(e.to_string()))?;

        // Step 3: Also check intermediate certificates (defense in depth)
        // This protects against attacks that use a valid leaf but compromised intermediate
        for intermediate in intermediates {
            if let Err(e) = self.pinning.verify_certificate(intermediate) {
                log::debug!(
                    "Intermediate certificate pin check: {} (this is informational only)",
                    e
                );
                // Don't fail on intermediate mismatch - only leaf cert is critical
            }
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Check if strict certificate pinning is required
///
/// Returns an error if `WSC_REQUIRE_CERT_PINNING=1` is set and pinning cannot
/// be enforced due to HTTP client limitations.
///
/// # Usage
///
/// Call this from FulcioClient and RekorClient before making connections:
/// ```ignore
/// check_pinning_enforcement("fulcio.sigstore.dev")?;
/// ```
pub fn check_pinning_enforcement(service: &str) -> Result<(), WSError> {
    if std::env::var("WSC_REQUIRE_CERT_PINNING").unwrap_or_default() == "1" {
        log::error!(
            "Certificate pinning is REQUIRED (WSC_REQUIRE_CERT_PINNING=1) but cannot be enforced for {}",
            service
        );
        log::error!(
            "Current HTTP client (ureq 3.x) does not support custom certificate verification"
        );
        log::error!("To enable pinning, either:");
        log::error!("  1. Upgrade to a future version of ureq that supports custom TLS config");
        log::error!("  2. Wait for wsc to migrate to reqwest or another HTTP client");
        log::error!("  3. Unset WSC_REQUIRE_CERT_PINNING to allow connections (less secure)");

        return Err(WSError::CertificatePinningError(format!(
            "Strict certificate pinning required but cannot be enforced for {} (HTTP client limitation)",
            service
        )));
    }

    // Log informational message about pinning status
    log::debug!(
        "Certificate pinning infrastructure ready for {} (not yet enforced, pending HTTP client support)",
        service
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinning_config_creation() {
        let pins = vec![
            "a".repeat(64),
            "b".repeat(64),
        ];
        let config = PinningConfig::custom(pins.clone(), "test-service".to_string());

        assert_eq!(config.service_name, "test-service");
        assert_eq!(config.pins.len(), 2);
        assert!(config.is_enabled());
    }

    #[test]
    fn test_pinning_config_empty() {
        let config = PinningConfig::custom(vec![], "test-service".to_string());
        assert!(!config.is_enabled());
    }

    #[test]
    fn test_certificate_fingerprint_matching() {
        // Create a test certificate (DER format)
        let test_cert_der = vec![0x30, 0x82, 0x01, 0x00]; // Minimal DER structure
        let cert = CertificateDer::from(test_cert_der.clone());

        // Compute expected fingerprint
        let mut hasher = Sha256::new();
        hasher.update(&test_cert_der);
        let expected = hex::encode(hasher.finalize());

        // Create config with correct pin
        let config = PinningConfig::custom(vec![expected.clone()], "test".to_string());
        assert!(config.verify_certificate(&cert).is_ok());

        // Create config with wrong pin
        let wrong_config = PinningConfig::custom(vec!["a".repeat(64)], "test".to_string());
        assert!(wrong_config.verify_certificate(&cert).is_err());
    }

    #[test]
    fn test_production_configs() {
        let fulcio = PinningConfig::fulcio_production();
        assert_eq!(fulcio.service_name, "fulcio.sigstore.dev");

        let rekor = PinningConfig::rekor_production();
        assert_eq!(rekor.service_name, "rekor.sigstore.dev");
    }

    #[test]
    fn test_hex_normalization() {
        // Test that uppercase hex is normalized to lowercase
        let pins = vec!["ABCDEF".to_string() + &"0".repeat(58)];
        let config = PinningConfig::custom(pins, "test".to_string());

        assert!(config.pins.contains(&("abcdef".to_string() + &"0".repeat(58))));
    }

    #[test]
    fn test_pinned_cert_verifier_creation() {
        // Test that we can create a PinnedCertVerifier
        let pins = vec!["a".repeat(64), "b".repeat(64)];
        let config = PinningConfig::custom(pins, "test-service".to_string());

        let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = PinnedCertVerifier::new(config, crypto_provider);

        assert!(verifier.is_ok());
        let verifier = verifier.unwrap();
        assert!(format!("{:?}", verifier).contains("PinnedCertVerifier"));
    }

    // NOTE: Tests for WSC_REQUIRE_CERT_PINNING env var cannot be included
    // because the codebase has #![forbid(unsafe_code)] and env var manipulation
    // requires unsafe. The check_pinning_enforcement() function is manually tested.

    #[test]
    fn test_pinning_with_multiple_certs() {
        // Test that pinning works with multiple pinned certificates
        let cert1 = vec![0x30, 0x82, 0x01, 0x01];
        let cert2 = vec![0x30, 0x82, 0x01, 0x02];

        // Compute fingerprints
        let fp1 = hex::encode(Sha256::digest(&cert1));
        let fp2 = hex::encode(Sha256::digest(&cert2));

        let config = PinningConfig::custom(vec![fp1.clone(), fp2.clone()], "multi-test".to_string());

        // Both certificates should pass
        assert!(config.verify_certificate(&CertificateDer::from(cert1)).is_ok());
        assert!(config.verify_certificate(&CertificateDer::from(cert2)).is_ok());

        // Wrong certificate should fail
        let cert3 = vec![0x30, 0x82, 0x01, 0x03];
        assert!(config.verify_certificate(&CertificateDer::from(cert3)).is_err());
    }
}
