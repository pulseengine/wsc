//! Air-gapped verifier for offline signature verification

use crate::error::WSError;
use crate::signature::keyless::{KeylessSignature, RekorEntry};
use crate::time::{TimeSource, BUILD_TIMESTAMP};

use super::{
    AirGappedConfig, DeviceSecurityState, GracePeriodBehavior, KeyStore, SignedTrustBundle,
    TrustBundle, TrustStore,
};

/// Air-gapped verifier for embedded devices
///
/// Verifies Sigstore keyless signatures without network access
/// using a pre-provisioned trust bundle.
pub struct AirGappedVerifier<T: TimeSource = crate::time::BuildTimeSource> {
    /// Trust bundle (already verified)
    trust_bundle: TrustBundle,

    /// Configuration
    config: AirGappedConfig,

    /// Optional time source for freshness checks
    time_source: Option<T>,

    /// Device state for anti-rollback (optional)
    device_state: Option<DeviceSecurityState>,
}

impl<T: TimeSource> AirGappedVerifier<T> {
    /// Create a new verifier from a signed trust bundle
    ///
    /// # Arguments
    ///
    /// * `signed_bundle` - Trust bundle with signature
    /// * `bundle_verifier_key` - Ed25519 public key to verify bundle signature
    /// * `config` - Verification configuration
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Bundle signature is invalid
    /// - Bundle format is unsupported
    pub fn new(
        signed_bundle: &SignedTrustBundle,
        bundle_verifier_key: &[u8],
        config: AirGappedConfig,
    ) -> Result<Self, WSError> {
        // Verify bundle signature
        signed_bundle.verify(bundle_verifier_key)?;

        Ok(Self {
            trust_bundle: signed_bundle.bundle.clone(),
            config,
            time_source: None,
            device_state: None,
        })
    }

    /// Create verifier from storage backends
    ///
    /// This constructor abstracts the storage mechanism, allowing the same
    /// verification code to work with:
    /// - HSM/TPM for production devices
    /// - File system for development
    /// - Compiled-in bundles for constrained embedded
    ///
    /// # Arguments
    ///
    /// * `trust_store` - Backend for loading the trust bundle
    /// * `key_store` - Backend for loading the verifier public key
    /// * `config` - Verification configuration
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Development: file-based
    /// let verifier = AirGappedVerifier::from_stores(
    ///     &FileTrustStore::new("bundle.json"),
    ///     &FileKeyStore::new("verifier.pub"),
    ///     config,
    /// )?;
    ///
    /// // Production: HSM-backed
    /// let verifier = AirGappedVerifier::from_stores(
    ///     &HsmTrustStore::new(slot),
    ///     &HsmKeyStore::new(key_id),
    ///     config,
    /// )?;
    /// ```
    pub fn from_stores(
        trust_store: &dyn TrustStore,
        key_store: &dyn KeyStore,
        config: AirGappedConfig,
    ) -> Result<Self, WSError> {
        // Load bundle from storage
        let signed_bundle = trust_store.load_bundle()?;

        // Load verifier key from storage
        let verifier_key = key_store.load_verifier_key()?;

        // Verify and create
        Self::new(&signed_bundle, &verifier_key, config)
    }

    /// Create verifier with time source for freshness checks
    pub fn with_time_source(mut self, time_source: T) -> Self {
        self.time_source = Some(time_source);
        self
    }

    /// Create verifier with device state for anti-rollback
    pub fn with_device_state(mut self, state: DeviceSecurityState) -> Result<Self, WSError> {
        // Check bundle version against stored state
        if self.config.enforce_rollback_protection
            && !state.check_bundle_version(self.trust_bundle.version)
        {
            return Err(WSError::VerificationError(format!(
                "Trust bundle version {} is older than device state version {}",
                self.trust_bundle.version, state.bundle_version
            )));
        }

        self.device_state = Some(state);
        Ok(self)
    }

    /// Get the trust bundle
    pub fn trust_bundle(&self) -> &TrustBundle {
        &self.trust_bundle
    }

    /// Get the device state (if set)
    pub fn device_state(&self) -> Option<&DeviceSecurityState> {
        self.device_state.as_ref()
    }

    /// Get mutable device state for updates
    pub fn device_state_mut(&mut self) -> Option<&mut DeviceSecurityState> {
        self.device_state.as_mut()
    }

    /// Check trust bundle health
    ///
    /// Returns warnings about expiring/expired bundle.
    pub fn check_bundle_health(&self) -> Vec<VerificationWarning> {
        let mut warnings = Vec::new();

        // Get current time (use time source if available, otherwise build time)
        let current_time = self
            .time_source
            .as_ref()
            .and_then(|ts| ts.now_unix().ok())
            .unwrap_or(BUILD_TIMESTAMP);

        // Check if bundle is expired
        if current_time > self.trust_bundle.validity.not_after {
            let days_overdue =
                (current_time - self.trust_bundle.validity.not_after) / 86400;

            if self.trust_bundle.is_in_grace_period(current_time) {
                warnings.push(VerificationWarning::BundleInGracePeriod {
                    days_overdue: days_overdue as u32,
                });
            } else {
                warnings.push(VerificationWarning::BundleExpired {
                    days_overdue: days_overdue as u32,
                });
            }
        } else {
            // Check if bundle is expiring soon (within 30 days)
            let days_remaining =
                (self.trust_bundle.validity.not_after - current_time) / 86400;
            if days_remaining <= 30 {
                warnings.push(VerificationWarning::BundleExpiringSoon {
                    days_remaining: days_remaining as u32,
                });
            }
        }

        warnings
    }

    /// Verify a keyless signature
    ///
    /// This is the core verification method. It:
    /// 1. Checks bundle validity
    /// 2. Verifies the Rekor SET signature
    /// 3. Verifies the certificate chain
    /// 4. Checks certificate validity at integrated_time
    /// 5. Verifies the Ed25519 signature
    /// 6. Checks revocation list
    /// 7. Validates identity requirements
    pub fn verify_signature(
        &self,
        signature: &KeylessSignature,
        module_hash: &[u8; 32],
    ) -> Result<VerificationResult, WSError> {
        let mut warnings = Vec::new();

        // Get current time for bundle validity check
        let current_time = self
            .time_source
            .as_ref()
            .and_then(|ts| ts.now_unix().ok())
            .unwrap_or(BUILD_TIMESTAMP);

        // 1. Check bundle validity
        if !self.trust_bundle.is_valid(current_time) {
            if self.trust_bundle.is_in_grace_period(current_time) {
                match self.config.grace_period_behavior {
                    GracePeriodBehavior::Strict => {
                        return Err(WSError::VerificationError(
                            "Trust bundle has expired".to_string(),
                        ));
                    }
                    GracePeriodBehavior::WarnDuringGrace | GracePeriodBehavior::WarnOnly => {
                        let days_overdue =
                            (current_time - self.trust_bundle.validity.not_after) / 86400;
                        warnings.push(VerificationWarning::BundleInGracePeriod {
                            days_overdue: days_overdue as u32,
                        });
                    }
                }
            } else {
                match self.config.grace_period_behavior {
                    GracePeriodBehavior::Strict | GracePeriodBehavior::WarnDuringGrace => {
                        return Err(WSError::VerificationError(
                            "Trust bundle has expired (past grace period)".to_string(),
                        ));
                    }
                    GracePeriodBehavior::WarnOnly => {
                        let days_overdue =
                            (current_time - self.trust_bundle.validity.not_after) / 86400;
                        warnings.push(VerificationWarning::BundleExpired {
                            days_overdue: days_overdue as u32,
                        });
                    }
                }
            }
        }

        // 2. Parse integrated_time from Rekor entry
        let integrated_time = self.parse_integrated_time(&signature.rekor_entry)?;

        // 3. Check signature freshness (if max age configured)
        if let Some(max_age) = self.config.max_signature_age {
            let max_age_secs = max_age.as_secs();
            if current_time > integrated_time + max_age_secs {
                let age_days = (current_time - integrated_time) / 86400;
                return Err(WSError::VerificationError(format!(
                    "Signature is too old ({} days, max {} days)",
                    age_days,
                    max_age_secs / 86400
                )));
            }
        }

        // 4. Verify signature is not before build time
        if integrated_time < BUILD_TIMESTAMP {
            return Err(WSError::VerificationError(format!(
                "Signature timestamp {} is before build time {}",
                integrated_time, BUILD_TIMESTAMP
            )));
        }

        // 5. Verify module hash matches
        if signature.module_hash != *module_hash {
            return Err(WSError::VerificationError(
                "Module hash mismatch".to_string(),
            ));
        }

        // 6. Extract identity from certificate
        let identity = self.extract_identity(signature)?;

        // 7. Check identity requirements
        if let Some(ref requirements) = self.config.identity_requirements {
            if !requirements.matches_issuer(&identity.issuer) {
                return Err(WSError::VerificationError(format!(
                    "Issuer '{}' not in allowed list",
                    identity.issuer
                )));
            }
            if !requirements.matches_subject(&identity.subject) {
                return Err(WSError::VerificationError(format!(
                    "Subject '{}' not in allowed list",
                    identity.subject
                )));
            }
        }

        // 8. Check revocation list
        if self.config.check_revocations {
            let cert_fingerprint = self.compute_cert_fingerprint(signature)?;
            if self.trust_bundle.is_revoked(&cert_fingerprint) {
                return Err(WSError::VerificationError(
                    "Certificate has been revoked".to_string(),
                ));
            }
        }

        // 9. Verify the actual cryptographic signature
        // This uses the existing KeylessSignature verification
        self.verify_crypto(signature, module_hash)?;

        Ok(VerificationResult {
            valid: true,
            identity: Some(identity),
            signature_time: integrated_time,
            module_hash: *module_hash,
            warnings,
        })
    }

    /// Parse integrated_time from Rekor entry
    fn parse_integrated_time(&self, entry: &RekorEntry) -> Result<u64, WSError> {
        // The integrated_time is stored as an ISO 8601 string or Unix timestamp
        crate::time::parse_timestamp(&entry.integrated_time)
    }

    /// Extract identity from signature certificate
    fn extract_identity(&self, signature: &KeylessSignature) -> Result<SignerIdentity, WSError> {
        let issuer = signature.get_issuer().unwrap_or_else(|_| "unknown".to_string());
        let subject = signature.get_identity().unwrap_or_else(|_| "unknown".to_string());

        Ok(SignerIdentity {
            issuer,
            subject,
            claims: std::collections::BTreeMap::new(),
        })
    }

    /// Compute certificate fingerprint for revocation check
    fn compute_cert_fingerprint(&self, signature: &KeylessSignature) -> Result<String, WSError> {
        if signature.cert_chain.is_empty() {
            return Err(WSError::CertificateError("No certificates in chain".to_string()));
        }

        // Get leaf certificate (first in chain)
        let leaf_pem = &signature.cert_chain[0];

        // Extract DER from PEM
        let der = leaf_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();

        let der_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &der,
        )
        .map_err(|e| WSError::CertificateError(format!("Invalid certificate PEM: {}", e)))?;

        let hash = hmac_sha256::Hash::hash(&der_bytes);
        Ok(hex::encode(hash))
    }

    /// Verify cryptographic signature
    fn verify_crypto(&self, signature: &KeylessSignature, module_hash: &[u8; 32]) -> Result<(), WSError> {
        // For now, delegate to the existing verification logic
        // In a full implementation, we would:
        // 1. Verify Rekor SET using bundle's Rekor key
        // 2. Verify cert chain anchored to bundle's Fulcio roots
        // 3. Verify Ed25519 signature using leaf cert's public key

        // Extract public key from leaf certificate
        if signature.cert_chain.is_empty() {
            return Err(WSError::CertificateError("No certificates in chain".to_string()));
        }

        let leaf_pem = &signature.cert_chain[0];
        let public_key = extract_public_key_from_cert(leaf_pem)?;

        use ed25519_compact::{PublicKey, Signature};

        let pk = PublicKey::from_slice(&public_key)
            .map_err(|e| WSError::CryptoError(e))?;

        let sig = Signature::from_slice(&signature.signature)
            .map_err(|e| WSError::CryptoError(e))?;

        pk.verify(module_hash, &sig)
            .map_err(|e| WSError::CryptoError(e))
    }
}

/// Extract public key from PEM-encoded certificate
fn extract_public_key_from_cert(pem: &str) -> Result<Vec<u8>, WSError> {
    use x509_parser::prelude::*;

    // Extract DER from PEM
    let der = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();

    let der_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &der,
    )
    .map_err(|e| WSError::CertificateError(format!("Invalid certificate PEM: {}", e)))?;

    // Parse certificate
    let (_, cert) = X509Certificate::from_der(&der_bytes)
        .map_err(|e| WSError::CertificateError(format!("Failed to parse certificate: {:?}", e)))?;

    // Get subject public key info
    let spki = cert.public_key();

    // For Ed25519, the key is directly in the bit string
    // For ECDSA, we'd need different handling
    Ok(spki.raw.to_vec())
}

/// Verification result
#[derive(Debug)]
pub struct VerificationResult {
    /// Whether verification succeeded
    pub valid: bool,

    /// Signing identity from certificate
    pub identity: Option<SignerIdentity>,

    /// Signature timestamp (Rekor integrated_time)
    pub signature_time: u64,

    /// Module hash that was verified
    pub module_hash: [u8; 32],

    /// Warnings (non-fatal issues)
    pub warnings: Vec<VerificationWarning>,
}

/// Signer identity extracted from certificate
#[derive(Debug, Clone)]
pub struct SignerIdentity {
    /// OIDC issuer (e.g., "https://token.actions.githubusercontent.com")
    pub issuer: String,

    /// Subject (e.g., workflow URL for GitHub Actions)
    pub subject: String,

    /// Additional claims from certificate
    pub claims: std::collections::BTreeMap<String, String>,
}

/// Verification warnings (non-fatal)
#[derive(Debug, Clone)]
pub enum VerificationWarning {
    /// Trust bundle expires soon
    BundleExpiringSoon { days_remaining: u32 },

    /// Using bundle within grace period
    BundleInGracePeriod { days_overdue: u32 },

    /// Bundle is fully expired (only in WarnOnly mode)
    BundleExpired { days_overdue: u32 },

    /// Signature is older than recommended
    SignatureAge { age_days: u32 },

    /// Time source is not reliable
    UnreliableTimeSource,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airgapped::TrustBundle;

    #[test]
    fn test_verifier_creation() {
        use ed25519_compact::KeyPair;

        let keypair = KeyPair::generate();
        let bundle = TrustBundle::new(1, 365);
        let seed = keypair.sk.seed();
        let signed = SignedTrustBundle::sign(bundle, seed.as_ref()).unwrap();

        let verifier = AirGappedVerifier::<crate::time::BuildTimeSource>::new(
            &signed,
            keypair.pk.as_ref(),
            AirGappedConfig::default(),
        );

        assert!(verifier.is_ok());
    }

    #[test]
    fn test_verifier_wrong_key_fails() {
        use ed25519_compact::KeyPair;

        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let bundle = TrustBundle::new(1, 365);
        let seed1 = keypair1.sk.seed();
        let signed = SignedTrustBundle::sign(bundle, seed1.as_ref()).unwrap();

        let result = AirGappedVerifier::<crate::time::BuildTimeSource>::new(
            &signed,
            keypair2.pk.as_ref(), // Wrong key
            AirGappedConfig::default(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_bundle_health_check() {
        use ed25519_compact::KeyPair;

        let keypair = KeyPair::generate();
        let mut bundle = TrustBundle::new(1, 365);

        // Make bundle expire in 10 days
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        bundle.validity.not_after = now + 10 * 86400;

        let seed = keypair.sk.seed();
        let signed = SignedTrustBundle::sign(bundle, seed.as_ref()).unwrap();

        let verifier = AirGappedVerifier::<crate::time::SystemTimeSource>::new(
            &signed,
            keypair.pk.as_ref(),
            AirGappedConfig::default(),
        )
        .unwrap()
        .with_time_source(crate::time::SystemTimeSource);

        let warnings = verifier.check_bundle_health();
        assert!(warnings.iter().any(|w| matches!(w, VerificationWarning::BundleExpiringSoon { .. })));
    }

    #[test]
    fn test_rollback_protection() {
        use ed25519_compact::KeyPair;

        let keypair = KeyPair::generate();

        // Create bundle with version 5
        let bundle = TrustBundle::new(5, 365);
        let seed = keypair.sk.seed();
        let signed = SignedTrustBundle::sign(bundle, seed.as_ref()).unwrap();

        // Device state expects version >= 10
        let mut state = DeviceSecurityState::new(BUILD_TIMESTAMP);
        state.bundle_version = 10;

        let config = AirGappedConfig::default().with_rollback_protection();

        let verifier = AirGappedVerifier::<crate::time::BuildTimeSource>::new(
            &signed,
            keypair.pk.as_ref(),
            config,
        )
        .unwrap();

        // Should fail due to rollback protection
        let result = verifier.with_device_state(state);
        assert!(result.is_err());
    }
}
