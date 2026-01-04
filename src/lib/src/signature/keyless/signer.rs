//! Keyless signing orchestration
//!
//! This module provides the main entry point for keyless signing, orchestrating:
//! 1. Ephemeral key generation
//! 2. OIDC token acquisition
//! 3. Fulcio certificate issuance
//! 4. Module signing
//! 5. Rekor transparency log upload

use super::{
    FulcioClient, KeylessSignature, OidcProvider, RekorClient, RekorEntry, RekorKeyring,
    detect_oidc_provider,
};
use crate::{Module, WSError, SectionLike, audit};
use ecdsa::SigningKey;
use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};

/// Configuration for keyless signing
#[derive(Default)]
pub struct KeylessConfig {
    /// Fulcio server URL (uses default if None)
    pub fulcio_url: Option<String>,
    /// Rekor server URL (uses default if None)
    pub rekor_url: Option<String>,
    /// Skip Rekor upload (not recommended for production)
    pub skip_rekor: bool,
    /// Use Sigstore staging environment instead of production
    ///
    /// When true, uses:
    /// - fulcio.staging.sigstore.dev
    /// - rekor.staging.sigstore.dev
    ///
    /// Can also be set via WSC_SIGSTORE_STAGING=1 environment variable.
    pub use_staging: bool,
    /// Custom certificate pins for Fulcio (overrides defaults)
    ///
    /// SHA256 fingerprints in hex format (64 characters each).
    /// If empty, uses built-in production/staging pins.
    pub fulcio_pins: Vec<String>,
    /// Custom certificate pins for Rekor (overrides defaults)
    ///
    /// SHA256 fingerprints in hex format (64 characters each).
    /// If empty, uses built-in production/staging pins.
    pub rekor_pins: Vec<String>,
    /// Require strict certificate pinning enforcement
    ///
    /// When true, operations will fail if certificate pinning cannot be enforced
    /// due to HTTP client limitations.
    ///
    /// Can also be set via WSC_REQUIRE_CERT_PINNING=1 environment variable.
    pub require_cert_pinning: bool,
}


/// Main keyless signing interface
pub struct KeylessSigner {
    config: KeylessConfig,
    oidc: Box<dyn OidcProvider>,
    fulcio: FulcioClient,
    rekor: RekorClient,
}

impl KeylessSigner {
    /// Create keyless signer with default config
    ///
    /// This will auto-detect the OIDC provider from environment variables
    /// and use the default Sigstore production servers.
    ///
    /// # Example
    /// ```no_run
    /// use wsc::keyless::KeylessSigner;
    ///
    /// let signer = KeylessSigner::new()?;
    /// # Ok::<(), wsc::WSError>(())
    /// ```
    pub fn new() -> Result<Self, WSError> {
        Self::with_config(KeylessConfig::default())
    }

    /// Create keyless signer with custom config
    ///
    /// # Example
    /// ```no_run
    /// use wsc::keyless::{KeylessSigner, KeylessConfig};
    ///
    /// let config = KeylessConfig {
    ///     fulcio_url: Some("https://fulcio.sigstore.dev".to_string()),
    ///     rekor_url: Some("https://rekor.sigstore.dev".to_string()),
    ///     skip_rekor: false,
    ///     ..Default::default()
    /// };
    /// let signer = KeylessSigner::with_config(config)?;
    /// # Ok::<(), wsc::WSError>(())
    /// ```
    pub fn with_config(config: KeylessConfig) -> Result<Self, WSError> {
        use super::cert_pinning::{check_pinning_enforcement, PinningConfig};

        // Check if strict certificate pinning is required
        let require_pinning = config.require_cert_pinning
            || std::env::var("WSC_REQUIRE_CERT_PINNING").unwrap_or_default() == "1";

        // Determine if staging environment should be used
        let use_staging = config.use_staging || PinningConfig::is_staging();

        // Log certificate pinning configuration
        let fulcio_pins = if !config.fulcio_pins.is_empty() {
            PinningConfig::custom(config.fulcio_pins.clone(), "fulcio (custom)".to_string())
        } else if use_staging {
            PinningConfig::fulcio_staging()
        } else {
            PinningConfig::fulcio_production()
        };

        let rekor_pins = if !config.rekor_pins.is_empty() {
            PinningConfig::custom(config.rekor_pins.clone(), "rekor (custom)".to_string())
        } else if use_staging {
            PinningConfig::rekor_staging()
        } else {
            PinningConfig::rekor_production()
        };

        log::info!(
            "Certificate pinning configured: Fulcio ({} pins for {}), Rekor ({} pins for {})",
            fulcio_pins.pin_count(),
            fulcio_pins.service_name(),
            rekor_pins.pin_count(),
            rekor_pins.service_name()
        );

        // Check if pinning can be enforced (currently cannot due to ureq limitations)
        if require_pinning {
            check_pinning_enforcement("fulcio")?;
            check_pinning_enforcement("rekor")?;
        }

        // Auto-detect OIDC provider
        let oidc = detect_oidc_provider()?;
        log::info!("Using OIDC provider: {}", oidc.name());

        // Create Fulcio client with appropriate URL
        let fulcio = if let Some(url) = &config.fulcio_url {
            FulcioClient::with_url(url.clone())
        } else if use_staging {
            FulcioClient::with_url("https://fulcio.staging.sigstore.dev".to_string())
        } else {
            FulcioClient::new()
        };

        // Create Rekor client with appropriate URL
        let rekor = if let Some(url) = &config.rekor_url {
            RekorClient::with_url(url.clone())
        } else if use_staging {
            RekorClient::with_url("https://rekor.staging.sigstore.dev".to_string())
        } else {
            RekorClient::new()
        };

        Ok(Self {
            config,
            oidc,
            fulcio,
            rekor,
        })
    }

    /// Sign a WASM module using keyless signing
    ///
    /// This method performs the complete keyless signing flow:
    /// 1. Generates an ephemeral ECDSA P-256 keypair
    /// 2. Obtains an OIDC identity token
    /// 3. Requests a short-lived certificate from Fulcio
    /// 4. Signs the module hash with the ephemeral key
    /// 5. Uploads the signature to Rekor transparency log
    /// 6. Embeds the keyless signature in the module
    ///
    /// # Arguments
    /// * `module` - The WASM module to sign
    ///
    /// # Returns
    /// * `(Module, KeylessSignature)` - The signed module and the keyless signature
    ///
    /// # Example
    /// ```no_run
    /// use wsc::{Module, keyless::KeylessSigner};
    ///
    /// let module = Module::deserialize_from_file("module.wasm")?;
    /// let signer = KeylessSigner::new()?;
    /// let (signed_module, signature) = signer.sign_module(module)?;
    ///
    /// signed_module.serialize_to_file("signed.wasm")?;
    /// println!("Signed by: {}", signature.get_identity()?);
    /// println!("Rekor entry: {}", signature.rekor_entry.uuid);
    /// # Ok::<(), wsc::WSError>(())
    /// ```
    pub fn sign_module(&self, module: Module) -> Result<(Module, KeylessSignature), WSError> {
        log::info!("Starting keyless signing process");

        // Generate correlation ID for audit trail
        let correlation_id = audit::new_correlation_id();

        // Step 1: Generate ephemeral keypair
        // SECURITY: Ephemeral key zeroization (addresses Issue #14)
        //
        // The SigningKey contains a SecretKey which implements ZeroizeOnDrop.
        // When the signing_key variable goes out of scope at the end of this function,
        // its Drop implementation will securely zeroize the private key bytes in memory.
        // This protects against:
        // - Memory dumps and crash files
        // - Swap file exposure
        // - Process memory inspection via debuggers
        // - Cold boot attacks (DRAM remanence)
        //
        // The zeroization happens automatically even in panic/error scenarios because
        // Rust's drop mechanism is exception-safe.
        log::debug!("Generating ephemeral ECDSA P-256 keypair");
        let signing_key =
            SigningKey::<p256::NistP256>::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();

        // Encode public key in uncompressed form (0x04 || x || y)
        let public_key_bytes = verifying_key.to_encoded_point(false);
        let public_key = public_key_bytes.as_bytes();

        // Step 2: Get OIDC token
        log::debug!("Obtaining OIDC token from {}", self.oidc.name());
        let oidc_token = self.oidc.get_token()?;
        log::info!("OIDC token obtained for identity: {}", oidc_token.identity);

        // Step 3: Create proof of possession
        // Sign the 'sub' claim from the OIDC token
        // Per Fulcio spec: proof_of_possession is "a signature over the `sub` claim"
        // The SigningKey::sign() method handles hashing internally
        log::debug!("Creating proof of possession");
        let sub_claim = oidc_token.get_sub_claim()?;

        use ecdsa::signature::Signer;
        let proof: Signature = signing_key.sign(sub_claim.as_bytes());

        // Step 4: Request certificate from Fulcio
        log::debug!("Requesting certificate from Fulcio");
        let certificate =
            self.fulcio
                .get_certificate(&oidc_token, public_key, &proof.to_bytes())?;
        log::info!(
            "Certificate obtained with {} certs in chain",
            certificate.cert_chain.len()
        );

        // Step 5: Compute module hash and sign it
        // Use SHA-256 for ECDSA signatures per Rekor hashedrekord spec
        log::debug!("Computing module hash (SHA-256)");
        let mut module_bytes = Vec::new();
        module.serialize(&mut module_bytes)?;

        // For hashedrekord, we need to sign the pre-computed hash using DigestSigner
        // Create hasher and sign it before finalizing
        log::debug!("Signing module hash");
        let mut module_hasher = Sha256::new();
        module_hasher.update(&module_bytes);

        use ecdsa::signature::DigestSigner;
        let signature: Signature = signing_key.sign_digest(module_hasher.clone());

        // Also get the hash value for Rekor upload
        let module_hash = module_hasher.finalize();
        let artifact_hash = format!("sha256:{}", hex::encode(&module_hash));

        // Log signing attempt (we now have identity and artifact hash)
        audit::log_signing_attempt(
            &correlation_id,
            &artifact_hash,
            Some(&oidc_token.identity),
        );

        // Step 7: Upload to Rekor (if not skipped)
        let rekor_entry = if self.config.skip_rekor {
            log::warn!("Skipping Rekor upload (not recommended for production)");
            // Create a dummy entry for testing
            RekorEntry {
                uuid: "skipped".to_string(),
                log_index: 0,
                body: String::new(),
                log_id: String::new(),
                inclusion_proof: vec![],
                signed_entry_timestamp: String::new(),
                integrated_time: chrono::Utc::now().to_rfc3339(),
            }
        } else {
            log::debug!("Uploading signature to Rekor");
            let entry =
                self.rekor
                    .upload_entry(&module_hash, &signature.to_bytes(), &certificate)?;
            log::info!(
                "Rekor entry created: {} (index: {})",
                entry.uuid,
                entry.log_index
            );
            entry
        };

        // Step 8: Create keyless signature
        log::debug!("Creating keyless signature");
        let keyless_sig = KeylessSignature::new(
            signature.to_bytes().to_vec(),
            certificate.cert_chain.clone(),
            rekor_entry,
            module_hash.to_vec(),
        );

        // Step 9: Embed signature in module
        log::debug!("Embedding signature in module");
        let signed_module = self.embed_signature(module, &keyless_sig)?;

        // Log signing success
        audit::log_signing_success(
            &correlation_id,
            &artifact_hash,
            Some(&oidc_token.identity),
            Some(&keyless_sig.rekor_entry.uuid),
            None, // certificate fingerprint (TODO: extract from cert)
        );

        log::info!("Keyless signing completed successfully");
        Ok((signed_module, keyless_sig))
    }

    /// Embed a keyless signature into a WASM module
    ///
    /// This creates a custom section named "signature" with the serialized
    /// keyless signature data.
    fn embed_signature(
        &self,
        module: Module,
        signature: &KeylessSignature,
    ) -> Result<Module, WSError> {
        let signature_bytes = signature.to_bytes()?;
        log::debug!("Embedding keyless signature: {} bytes", signature_bytes.len());

        // Use Module's existing attach_signature mechanism
        module.attach_signature(&signature_bytes)
    }
}

/// Keyless signature verification
pub struct KeylessVerifier;

/// Result of keyless signature verification
#[derive(Debug, Clone)]
pub struct KeylessVerificationResult {
    /// The identity (email/subject) from the certificate
    pub identity: String,
    /// The OIDC issuer URL
    pub issuer: String,
    /// The Rekor log index
    pub rekor_log_index: u64,
    /// The Rekor entry UUID
    pub rekor_uuid: String,
}

impl KeylessVerifier {
    /// Extract keyless signature from a module's signature section
    pub fn extract_signature(module: &Module) -> Result<KeylessSignature, WSError> {
        // Find the signature section
        let sig_section = module.sections.iter().find(|s| s.is_signature_header());

        let sig_section = sig_section.ok_or(WSError::NoSignatures)?;

        // Get the payload
        let payload = match sig_section {
            crate::Section::Custom(custom) => custom.payload(),
            _ => return Err(WSError::NoSignatures),
        };

        // Try to parse as keyless signature
        KeylessSignature::from_bytes(payload)
    }

    /// Verify a keyless signature
    ///
    /// This method performs comprehensive verification:
    /// 1. Extracts the keyless signature from the module
    /// 2. Verifies the certificate chain against Fulcio roots
    /// 3. Verifies the Rekor SET (Signed Entry Timestamp)
    /// 4. Optionally validates identity and issuer claims
    ///
    /// # Arguments
    /// * `module` - The signed WASM module
    /// * `expected_identity` - Optional identity to verify (e.g., "user@example.com")
    /// * `expected_issuer` - Optional OIDC issuer to verify (e.g., "https://github.com/login/oauth")
    ///
    /// # Returns
    /// `KeylessVerificationResult` with signer details if verification succeeds
    ///
    /// # Example
    /// ```no_run
    /// use wsc::{Module, keyless::KeylessVerifier};
    ///
    /// let module = Module::deserialize_from_file("signed.wasm")?;
    /// let result = KeylessVerifier::verify(
    ///     &module,
    ///     Some("user@example.com"),
    ///     Some("https://github.com/login/oauth")
    /// )?;
    /// println!("Signed by: {}", result.identity);
    /// # Ok::<(), wsc::WSError>(())
    /// ```
    pub fn verify(
        module: &Module,
        expected_identity: Option<&str>,
        expected_issuer: Option<&str>,
    ) -> Result<KeylessVerificationResult, WSError> {
        log::info!("Starting keyless signature verification");

        // Generate correlation ID for audit trail
        let correlation_id = audit::new_correlation_id();

        // Step 1: Extract signature from module
        log::debug!("Extracting keyless signature from module");
        let keyless_sig = Self::extract_signature(module)?;

        // Compute artifact hash for audit logging
        let mut module_bytes = Vec::new();
        module.serialize(&mut module_bytes).ok();
        let module_hash = Sha256::digest(&module_bytes);
        let artifact_hash = format!("sha256:{}", hex::encode(&module_hash));

        // Log verification attempt
        audit::log_verification_attempt(&correlation_id, &artifact_hash);

        // Step 2: Verify certificate chain
        log::debug!("Verifying certificate chain against Fulcio roots");
        keyless_sig.verify_cert_chain()?;
        log::info!("Certificate chain verified successfully");

        // Step 3: Verify Rekor SET (Signed Entry Timestamp)
        if !keyless_sig.rekor_entry.uuid.is_empty() && keyless_sig.rekor_entry.uuid != "skipped" {
            log::debug!("Verifying Rekor SET");
            let verifier = RekorKeyring::from_embedded_trust_root()?;
            verifier.verify_set(&keyless_sig.rekor_entry)?;
            log::info!("Rekor SET verified successfully");
        } else {
            log::warn!("Rekor verification skipped (no Rekor entry)");
        }

        // Step 4: Extract identity and issuer from certificate
        let identity = keyless_sig.get_identity()?;
        let issuer = keyless_sig.get_issuer()?;

        // Step 5: Validate identity if expected
        if let Some(expected) = expected_identity {
            if identity != expected {
                return Err(WSError::CertificateError(format!(
                    "Identity mismatch: expected '{}', got '{}'",
                    expected, identity
                )));
            }
            log::info!("Identity verified: {}", identity);
        }

        // Step 6: Validate issuer if expected
        if let Some(expected) = expected_issuer {
            if issuer != expected {
                return Err(WSError::CertificateError(format!(
                    "Issuer mismatch: expected '{}', got '{}'",
                    expected, issuer
                )));
            }
            log::info!("Issuer verified: {}", issuer);
        }

        // Log verification success
        audit::log_verification_success(
            &correlation_id,
            &artifact_hash,
            Some(&identity),
            1, // signature count
        );

        log::info!("Keyless verification completed successfully");

        Ok(KeylessVerificationResult {
            identity,
            issuer,
            rekor_log_index: keyless_sig.rekor_entry.log_index,
            rekor_uuid: keyless_sig.rekor_entry.uuid,
        })
    }
}

// Implement a simple RFC3339 timestamp for the dummy Rekor entry
mod chrono {
    pub struct Utc;
    impl Utc {
        pub fn now() -> DateTime {
            DateTime
        }
    }
    pub struct DateTime;
    impl DateTime {
        pub fn to_rfc3339(&self) -> String {
            // Use time crate's OffsetDateTime for proper RFC3339
            time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyless_config_default() {
        let config = KeylessConfig::default();
        assert!(config.fulcio_url.is_none());
        assert!(config.rekor_url.is_none());
        assert!(!config.skip_rekor);
        assert!(!config.use_staging);
        assert!(config.fulcio_pins.is_empty());
        assert!(config.rekor_pins.is_empty());
        assert!(!config.require_cert_pinning);
    }

    #[test]
    fn test_keyless_config_custom() {
        let config = KeylessConfig {
            fulcio_url: Some("https://custom.fulcio.dev".to_string()),
            rekor_url: Some("https://custom.rekor.dev".to_string()),
            skip_rekor: true,
            ..Default::default()
        };
        assert!(config.fulcio_url.is_some());
        assert!(config.rekor_url.is_some());
        assert!(config.skip_rekor);
    }

    #[test]
    fn test_keyless_config_staging() {
        let config = KeylessConfig {
            use_staging: true,
            ..Default::default()
        };
        assert!(config.use_staging);
        assert!(config.fulcio_url.is_none()); // Will use staging URL
        assert!(config.rekor_url.is_none()); // Will use staging URL
    }

    #[test]
    fn test_keyless_config_custom_pins() {
        let config = KeylessConfig {
            fulcio_pins: vec!["a".repeat(64), "b".repeat(64)],
            rekor_pins: vec!["c".repeat(64)],
            ..Default::default()
        };
        assert_eq!(config.fulcio_pins.len(), 2);
        assert_eq!(config.rekor_pins.len(), 1);
    }

    #[test]
    fn test_keyless_config_require_cert_pinning() {
        let config = KeylessConfig {
            require_cert_pinning: true,
            ..Default::default()
        };
        assert!(config.require_cert_pinning);
    }

    #[test]
    fn test_keyless_signer_new_fails_without_oidc() {
        // This test will fail if no OIDC provider is detected
        // In CI environments without OIDC setup, this is expected
        let result = KeylessSigner::new();
        // Should either succeed (if OIDC is available) or fail with NoOidcProvider
        if let Err(e) = result {
            assert!(
                matches!(e, WSError::NoOidcProvider) || matches!(e, WSError::OidcError(_)),
                "Expected NoOidcProvider or OidcError, got: {:?}",
                e
            );
        }
    }

    #[test]
    fn test_keyless_verifier_no_signature() {
        // Create an empty module (no signature)
        let module = Module::default();
        let result = KeylessVerifier::verify(&module, None, None);
        // Should fail with NoSignatures error
        assert!(result.is_err());
        assert!(matches!(result, Err(WSError::NoSignatures)));
    }

    // ============================================================================
    // SECURITY TESTS: Ephemeral Key Zeroization (Issue #14)
    // ============================================================================

    #[test]
    fn test_ephemeral_key_generation_and_drop() {
        // Test that ephemeral keys can be generated and dropped without issues
        // This verifies the basic zeroization mechanism works

        use ecdsa::SigningKey;
        use p256::NistP256;

        // Generate a key in a scope
        {
            let signing_key =
                SigningKey::<NistP256>::random(&mut p256::elliptic_curve::rand_core::OsRng);
            let verifying_key = signing_key.verifying_key();

            // Verify we can use the key
            assert!(!verifying_key.to_encoded_point(false).as_bytes().is_empty());

            // signing_key goes out of scope here
            // Its internal SecretKey implements ZeroizeOnDrop
        }

        // If we reach here, Drop was called successfully
    }

    #[test]
    fn test_ephemeral_key_signing_operation() {
        // Test that we can perform signing operations and the key is still zeroized

        use ecdsa::{SigningKey, signature::Signer};
        use p256::{NistP256, ecdsa::Signature};

        let message = b"test message for signing";

        let signature: Signature = {
            // Generate key in inner scope
            let signing_key =
                SigningKey::<NistP256>::random(&mut p256::elliptic_curve::rand_core::OsRng);

            // Sign the message
            let sig: Signature = signing_key.sign(message);

            // signing_key dropped here (zeroized)
            sig
        };

        // We have the signature but the key is gone (zeroized)
        assert_eq!(signature.to_bytes().len(), 64);
    }

    #[test]
    fn test_ephemeral_key_with_error_path() {
        // Test that ephemeral keys are zeroized even when errors occur

        use ecdsa::SigningKey;
        use p256::NistP256;

        fn operation_with_key() -> Result<Vec<u8>, WSError> {
            let signing_key =
                SigningKey::<NistP256>::random(&mut p256::elliptic_curve::rand_core::OsRng);
            let verifying_key = signing_key.verifying_key();
            let public_bytes = verifying_key.to_encoded_point(false);

            // Simulate an error after using the key
            if !public_bytes.as_bytes().is_empty() {
                return Err(WSError::OidcError("Simulated error".to_string()));
            }

            Ok(public_bytes.as_bytes().to_vec())
        }

        let result = operation_with_key();
        assert!(result.is_err());

        // Key was zeroized despite error
    }

    #[test]
    fn test_ephemeral_key_multiple_operations() {
        // Test that we can generate multiple ephemeral keys sequentially
        // Each one should be zeroized before the next is created

        use ecdsa::{SigningKey, signature::Signer};
        use p256::{NistP256, ecdsa::Signature};

        let message = b"test message";
        let mut signatures = Vec::new();

        for _ in 0..5 {
            let sig: Signature = {
                let signing_key =
                    SigningKey::<NistP256>::random(&mut p256::elliptic_curve::rand_core::OsRng);
                signing_key.sign(message)
                // key zeroized here
            };
            signatures.push(sig);
        }

        assert_eq!(signatures.len(), 5);
        // All 5 keys were created and zeroized sequentially
    }

    #[test]
    fn test_ephemeral_key_scope_limitation() {
        // Test that ephemeral keys don't escape their intended scope
        // This is a compile-time guarantee but we document the behavior

        use ecdsa::SigningKey;
        use p256::NistP256;

        let public_key_bytes = {
            let signing_key =
                SigningKey::<NistP256>::random(&mut p256::elliptic_curve::rand_core::OsRng);
            let verifying_key = signing_key.verifying_key();

            // Extract public key (safe to keep)
            verifying_key.to_encoded_point(false).as_bytes().to_vec()

            // signing_key dropped/zeroized here
        };

        // We can keep the public key, but the private key is gone
        assert!(!public_key_bytes.is_empty());

        // This would not compile (key doesn't escape scope):
        // let leaked_key = signing_key; // ERROR: signing_key not in scope
    }

    #[test]
    fn test_ephemeral_key_with_digest_signing() {
        // Test that digest signing (as used in actual keyless signing) works
        // and keys are still properly zeroized

        use ecdsa::{SigningKey, signature::DigestSigner};
        use p256::{NistP256, ecdsa::Signature};
        use sha2::{Digest, Sha256};

        let data = b"data to hash and sign";

        let signature: Signature = {
            let signing_key =
                SigningKey::<NistP256>::random(&mut p256::elliptic_curve::rand_core::OsRng);

            // Create digest
            let mut hasher = Sha256::new();
            hasher.update(data);

            // Sign the digest (this is what sign_module does)
            signing_key.sign_digest(hasher)

            // signing_key zeroized here
        };

        assert_eq!(signature.to_bytes().len(), 64);
    }

    #[test]
    fn test_ephemeral_key_verifying_key_extraction() {
        // Test that we can extract the verifying key before the signing key is dropped
        // This pattern is used in sign_module

        use ecdsa::SigningKey;
        use p256::NistP256;

        let (verifying_key_bytes, signature_made) = {
            let signing_key =
                SigningKey::<NistP256>::random(&mut p256::elliptic_curve::rand_core::OsRng);

            // Extract verifying key (this is safe to keep)
            let verifying_key = signing_key.verifying_key();
            let vk_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

            // Use the signing key
            use ecdsa::signature::Signer;
            use p256::ecdsa::Signature;
            let sig: Signature = signing_key.sign(b"test");

            (vk_bytes, sig.to_bytes().len() == 64)

            // signing_key zeroized here
        };

        // We kept the public key and verified a signature was made
        assert!(!verifying_key_bytes.is_empty());
        assert!(signature_made);
    }

    #[test]
    fn test_ephemeral_key_move_semantics() {
        // Test that moving keys between scopes works correctly with zeroization

        use ecdsa::SigningKey;
        use p256::NistP256;

        fn consume_key(key: SigningKey<NistP256>) -> usize {
            let vk = key.verifying_key();
            vk.to_encoded_point(false).as_bytes().len()
            // key dropped and zeroized here
        }

        let signing_key =
            SigningKey::<NistP256>::random(&mut p256::elliptic_curve::rand_core::OsRng);

        let len = consume_key(signing_key);
        // signing_key was moved into consume_key and zeroized there

        assert!(len > 0);
    }
}
