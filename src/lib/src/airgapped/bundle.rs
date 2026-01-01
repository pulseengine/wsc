//! Trust Bundle data structures
//!
//! A Trust Bundle is a signed, versioned container of trust anchors
//! for offline Sigstore signature verification.

use crate::error::WSError;
use serde::{Deserialize, Serialize};

/// Current trust bundle format version
pub const TRUST_BUNDLE_FORMAT_VERSION: u8 = 1;

/// Trust bundle containing all trust anchors for offline verification
///
/// This structure contains:
/// - Fulcio root certificates (to anchor certificate chains)
/// - Rekor public keys (to verify Signed Entry Timestamps)
/// - Revocation list (certificate fingerprints to reject)
/// - Validity period with grace period support
///
/// The bundle is versioned for anti-rollback protection - devices reject
/// bundles with a version lower than their stored version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBundle {
    /// Format version for forward compatibility
    pub format_version: u8,

    /// Monotonically increasing bundle version (anti-rollback)
    ///
    /// Devices must reject bundles with `version < stored_version`.
    /// Increment this on every bundle update.
    pub version: u32,

    /// Unique bundle identifier (SHA-256 of canonical form, hex-encoded)
    #[serde(default)]
    pub bundle_id: String,

    /// When this bundle was created (Unix timestamp)
    pub created_at: u64,

    /// Bundle validity period
    pub validity: ValidityPeriod,

    /// Fulcio certificate authorities
    ///
    /// Contains root and intermediate certificates used to anchor
    /// the certificate chains in keyless signatures.
    pub certificate_authorities: Vec<CertificateAuthority>,

    /// Rekor transparency log configurations
    ///
    /// Contains public keys for verifying Signed Entry Timestamps.
    pub transparency_logs: Vec<TransparencyLog>,

    /// Revoked certificate fingerprints
    ///
    /// SHA-256 hashes of DER-encoded leaf certificates that should
    /// be rejected even if otherwise valid. Hex-encoded.
    #[serde(default)]
    pub revocations: Vec<String>,
}

impl TrustBundle {
    /// Create a new empty trust bundle
    pub fn new(version: u32, validity_days: u32) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            format_version: TRUST_BUNDLE_FORMAT_VERSION,
            version,
            bundle_id: String::new(),
            created_at: now,
            validity: ValidityPeriod {
                not_before: now,
                not_after: now + (validity_days as u64 * 86400),
                grace_period_seconds: 30 * 86400, // 30 days default
            },
            certificate_authorities: Vec::new(),
            transparency_logs: Vec::new(),
            revocations: Vec::new(),
        }
    }

    /// Add a certificate authority
    pub fn add_certificate_authority(&mut self, ca: CertificateAuthority) {
        self.certificate_authorities.push(ca);
    }

    /// Add a transparency log
    pub fn add_transparency_log(&mut self, log: TransparencyLog) {
        self.transparency_logs.push(log);
    }

    /// Add a revoked certificate fingerprint
    pub fn add_revocation(&mut self, fingerprint: String) {
        if !self.revocations.contains(&fingerprint) {
            self.revocations.push(fingerprint);
        }
    }

    /// Check if the bundle is currently valid
    pub fn is_valid(&self, current_time: u64) -> bool {
        current_time >= self.validity.not_before && current_time <= self.validity.not_after
    }

    /// Check if the bundle is in grace period
    pub fn is_in_grace_period(&self, current_time: u64) -> bool {
        current_time > self.validity.not_after
            && current_time <= self.validity.not_after + self.validity.grace_period_seconds
    }

    /// Check if a certificate fingerprint is revoked
    pub fn is_revoked(&self, fingerprint: &str) -> bool {
        self.revocations.iter().any(|r| r == fingerprint)
    }

    /// Compute bundle ID (SHA-256 of canonical JSON)
    pub fn compute_bundle_id(&mut self) -> Result<(), WSError> {
        // Temporarily clear bundle_id for canonical form
        let old_id = std::mem::take(&mut self.bundle_id);

        let canonical = serde_json::to_vec(self)
            .map_err(|e| WSError::InternalError(format!("Failed to serialize bundle: {}", e)))?;

        let hash = hmac_sha256::Hash::hash(&canonical);
        self.bundle_id = hex::encode(hash);

        // Restore if computation failed
        if self.bundle_id.is_empty() {
            self.bundle_id = old_id;
        }

        Ok(())
    }

    /// Serialize to JSON bytes
    pub fn to_json(&self) -> Result<Vec<u8>, WSError> {
        serde_json::to_vec_pretty(self)
            .map_err(|e| WSError::InternalError(format!("Failed to serialize bundle: {}", e)))
    }

    /// Deserialize from JSON bytes
    pub fn from_json(data: &[u8]) -> Result<Self, WSError> {
        serde_json::from_slice(data)
            .map_err(|e| WSError::InternalError(format!("Failed to parse bundle: {}", e)))
    }
}

/// Validity period with grace period support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidityPeriod {
    /// Start of validity (Unix timestamp)
    pub not_before: u64,

    /// End of validity (Unix timestamp)
    pub not_after: u64,

    /// Grace period after `not_after` (seconds)
    ///
    /// During the grace period, verification succeeds with warnings.
    /// This allows time for bundle updates without hard failures.
    #[serde(default)]
    pub grace_period_seconds: u64,
}

/// Certificate authority entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthority {
    /// Human-readable name (e.g., "Sigstore Public Good Instance")
    pub name: String,

    /// URI identifier (e.g., "https://fulcio.sigstore.dev")
    pub uri: String,

    /// PEM-encoded certificates (root and intermediates)
    ///
    /// Multiple certificates can be included for chain building.
    pub certificates_pem: Vec<String>,

    /// Validity period for this CA
    ///
    /// Used for historical verification - old signatures may use
    /// older CA certificates that are no longer active.
    pub valid_for: ValidityPeriod,
}

impl CertificateAuthority {
    /// Create a new CA entry from PEM certificates
    pub fn new(name: &str, uri: &str, pem_certs: Vec<String>, validity_days: u32) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            name: name.to_string(),
            uri: uri.to_string(),
            certificates_pem: pem_certs,
            valid_for: ValidityPeriod {
                not_before: now,
                not_after: now + (validity_days as u64 * 86400),
                grace_period_seconds: 0,
            },
        }
    }
}

/// Transparency log entry (Rekor)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyLog {
    /// Base URL (e.g., "https://rekor.sigstore.dev")
    pub base_url: String,

    /// Hash algorithm used (e.g., "sha256")
    pub hash_algorithm: String,

    /// PEM-encoded public key for SET verification
    pub public_key_pem: String,

    /// Log ID (SHA-256 of public key, hex-encoded)
    pub log_id: String,

    /// Validity period for this key
    pub valid_for: ValidityPeriod,
}

impl TransparencyLog {
    /// Create a new transparency log entry
    pub fn new(base_url: &str, public_key_pem: &str, validity_days: u32) -> Result<Self, WSError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Compute log ID from public key
        let log_id = Self::compute_log_id(public_key_pem)?;

        Ok(Self {
            base_url: base_url.to_string(),
            hash_algorithm: "sha256".to_string(),
            public_key_pem: public_key_pem.to_string(),
            log_id,
            valid_for: ValidityPeriod {
                not_before: now,
                not_after: now + (validity_days as u64 * 86400),
                grace_period_seconds: 0,
            },
        })
    }

    /// Compute log ID from PEM-encoded public key
    fn compute_log_id(pem: &str) -> Result<String, WSError> {
        // Extract DER from PEM
        let der = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();

        let der_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &der,
        )
        .map_err(|e| WSError::InternalError(format!("Invalid PEM encoding: {}", e)))?;

        let hash = hmac_sha256::Hash::hash(&der_bytes);
        Ok(hex::encode(hash))
    }
}

/// Signed trust bundle for secure distribution
///
/// The bundle is signed with a long-lived offline key. Devices verify
/// the signature against a pre-provisioned public key before using
/// the bundle contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTrustBundle {
    /// The trust bundle
    pub bundle: TrustBundle,

    /// Signature over the bundle
    pub signature: BundleSignature,
}

impl SignedTrustBundle {
    /// Create a signed bundle
    pub fn sign(bundle: TrustBundle, signing_key: &[u8]) -> Result<Self, WSError> {
        let bundle_bytes = bundle.to_json()?;
        let signature = BundleSignature::sign(&bundle_bytes, signing_key)?;

        Ok(Self { bundle, signature })
    }

    /// Verify the bundle signature
    pub fn verify(&self, verifier_key: &[u8]) -> Result<(), WSError> {
        let bundle_bytes = self.bundle.to_json()?;
        self.signature.verify(&bundle_bytes, verifier_key)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<Vec<u8>, WSError> {
        serde_json::to_vec_pretty(self)
            .map_err(|e| WSError::InternalError(format!("Failed to serialize signed bundle: {}", e)))
    }

    /// Deserialize from JSON
    pub fn from_json(data: &[u8]) -> Result<Self, WSError> {
        serde_json::from_slice(data)
            .map_err(|e| WSError::InternalError(format!("Failed to parse signed bundle: {}", e)))
    }
}

/// Signature over trust bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSignature {
    /// Key identifier (first 8 hex chars of SHA-256 of public key)
    pub key_id: String,

    /// Signature algorithm
    pub algorithm: SignatureAlgorithm,

    /// Raw signature bytes (base64-encoded)
    pub signature: String,
}

impl BundleSignature {
    /// Sign data with Ed25519 key
    pub fn sign(data: &[u8], secret_key: &[u8]) -> Result<Self, WSError> {
        use ed25519_compact::{KeyPair, Seed};

        // Create keypair from secret key bytes
        let seed = if secret_key.len() == 32 {
            Seed::from_slice(secret_key)
                .map_err(|e| WSError::CryptoError(e))?
        } else if secret_key.len() == 64 {
            // Full keypair format - extract seed
            Seed::from_slice(&secret_key[..32])
                .map_err(|e| WSError::CryptoError(e))?
        } else {
            return Err(WSError::InvalidArgument);
        };

        let keypair = KeyPair::from_seed(seed);

        // Compute key ID
        let pk_bytes = keypair.pk.as_ref();
        let key_hash = hmac_sha256::Hash::hash(pk_bytes);
        let key_id = hex::encode(&key_hash[..4]);

        // Sign
        let sig = keypair.sk.sign(data, None);
        let signature = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            sig.as_ref(),
        );

        Ok(Self {
            key_id,
            algorithm: SignatureAlgorithm::Ed25519,
            signature,
        })
    }

    /// Verify signature
    pub fn verify(&self, data: &[u8], public_key: &[u8]) -> Result<(), WSError> {
        use ed25519_compact::{PublicKey, Signature};

        match self.algorithm {
            SignatureAlgorithm::Ed25519 => {
                let pk = PublicKey::from_slice(public_key)
                    .map_err(|e| WSError::CryptoError(e))?;

                let sig_bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &self.signature,
                )
                .map_err(|_| WSError::InvalidArgument)?;

                let sig = Signature::from_slice(&sig_bytes)
                    .map_err(|e| WSError::CryptoError(e))?;

                pk.verify(data, &sig)
                    .map_err(|e| WSError::CryptoError(e))
            }
            _ => Err(WSError::UnsupportedAlgorithm(format!("{:?}", self.algorithm))),
        }
    }
}

/// Supported signature algorithms for bundles
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Ed25519 (recommended for embedded - small keys and signatures)
    Ed25519,
    /// ECDSA with P-256 curve
    EcdsaP256Sha256,
    /// ECDSA with P-384 curve
    EcdsaP384Sha384,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_bundle_creation() {
        let bundle = TrustBundle::new(1, 365);
        assert_eq!(bundle.format_version, TRUST_BUNDLE_FORMAT_VERSION);
        assert_eq!(bundle.version, 1);
        assert!(bundle.is_valid(bundle.created_at));
    }

    #[test]
    fn test_trust_bundle_validity() {
        let mut bundle = TrustBundle::new(1, 365);
        bundle.validity.not_before = 1000;
        bundle.validity.not_after = 2000;
        bundle.validity.grace_period_seconds = 500;

        assert!(!bundle.is_valid(500)); // Before not_before
        assert!(bundle.is_valid(1500)); // Within validity
        assert!(!bundle.is_valid(2500)); // After not_after

        assert!(!bundle.is_in_grace_period(1500)); // Still valid
        assert!(bundle.is_in_grace_period(2100)); // In grace period
        assert!(!bundle.is_in_grace_period(2600)); // Past grace period
    }

    #[test]
    fn test_trust_bundle_revocation() {
        let mut bundle = TrustBundle::new(1, 365);
        bundle.add_revocation("abc123".to_string());

        assert!(bundle.is_revoked("abc123"));
        assert!(!bundle.is_revoked("def456"));
    }

    #[test]
    fn test_trust_bundle_json_roundtrip() {
        let mut bundle = TrustBundle::new(1, 365);
        bundle.add_certificate_authority(CertificateAuthority::new(
            "Test CA",
            "https://example.com",
            vec!["-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string()],
            365,
        ));

        let json = bundle.to_json().unwrap();
        let parsed = TrustBundle::from_json(&json).unwrap();

        assert_eq!(parsed.version, bundle.version);
        assert_eq!(parsed.certificate_authorities.len(), 1);
    }

    #[test]
    fn test_signed_bundle_roundtrip() {
        use ed25519_compact::KeyPair;

        // Generate test keypair
        let keypair = KeyPair::generate();
        let seed = keypair.sk.seed();
        let secret_key = seed.as_ref();

        let bundle = TrustBundle::new(1, 365);
        let signed = SignedTrustBundle::sign(bundle, secret_key).unwrap();

        // Verify with correct key
        let public_key = keypair.pk.as_ref();
        assert!(signed.verify(public_key).is_ok());

        // Verify roundtrip
        let json = signed.to_json().unwrap();
        let parsed = SignedTrustBundle::from_json(&json).unwrap();
        assert!(parsed.verify(public_key).is_ok());
    }

    #[test]
    fn test_signed_bundle_wrong_key_fails() {
        use ed25519_compact::KeyPair;

        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let bundle = TrustBundle::new(1, 365);
        let seed1 = keypair1.sk.seed();
        let signed = SignedTrustBundle::sign(bundle, seed1.as_ref()).unwrap();

        // Wrong key should fail
        let result = signed.verify(keypair2.pk.as_ref());
        assert!(result.is_err());
    }
}
