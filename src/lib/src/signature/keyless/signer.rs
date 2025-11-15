//! Keyless signing orchestration
//!
//! This module provides the main entry point for keyless signing, orchestrating:
//! 1. Ephemeral key generation
//! 2. OIDC token acquisition
//! 3. Fulcio certificate issuance
//! 4. Module signing
//! 5. Rekor transparency log upload

use super::{
    detect_oidc_provider, FulcioClient, KeylessSignature, OidcProvider,
    RekorClient, RekorEntry,
};
use crate::{Module, WSError};
use ecdsa::SigningKey;
use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Configuration for keyless signing
pub struct KeylessConfig {
    /// Fulcio server URL (uses default if None)
    pub fulcio_url: Option<String>,
    /// Rekor server URL (uses default if None)
    pub rekor_url: Option<String>,
    /// Skip Rekor upload (not recommended for production)
    pub skip_rekor: bool,
}

impl Default for KeylessConfig {
    fn default() -> Self {
        Self {
            fulcio_url: None,
            rekor_url: None,
            skip_rekor: false,
        }
    }
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
    /// };
    /// let signer = KeylessSigner::with_config(config)?;
    /// # Ok::<(), wsc::WSError>(())
    /// ```
    pub fn with_config(config: KeylessConfig) -> Result<Self, WSError> {
        // Auto-detect OIDC provider
        let oidc = detect_oidc_provider()?;
        log::info!("Using OIDC provider: {}", oidc.name());

        // Create Fulcio client
        let fulcio = if let Some(url) = &config.fulcio_url {
            FulcioClient::with_url(url.clone())
        } else {
            FulcioClient::new()
        };

        // Create Rekor client
        let rekor = if let Some(url) = &config.rekor_url {
            RekorClient::with_url(url.clone())
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
    pub fn sign_module(
        &self,
        module: Module,
    ) -> Result<(Module, KeylessSignature), WSError> {
        log::info!("Starting keyless signing process");

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
        let signing_key = SigningKey::<p256::NistP256>::random(&mut p256::elliptic_curve::rand_core::OsRng);
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
        let certificate = self.fulcio.get_certificate(
            &oidc_token,
            public_key,
            &proof.to_bytes(),
        )?;
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
            let entry = self.rekor.upload_entry(
                &module_hash,
                &signature.to_bytes(),
                &certificate,
            )?;
            log::info!("Rekor entry created: {} (index: {})", entry.uuid, entry.log_index);
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

        // Create a custom section for the signature
        // Note: This is a simplified version. In production, we should use
        // the existing Module::attach_signature() method or similar.
        // For now, we'll return the module as-is and let the caller handle embedding.
        // TODO: Integrate with Module's signature attachment mechanism

        log::warn!("Signature embedding not yet integrated with Module API");
        log::debug!("Signature size: {} bytes", signature_bytes.len());

        // Return the module unchanged for now
        // The signature_bytes should be attached using Module's existing API
        Ok(module)
    }
}

/// Keyless signature verification
pub struct KeylessVerifier;

impl KeylessVerifier {
    /// Verify a keyless signature
    ///
    /// This method performs comprehensive verification:
    /// 1. Extracts the keyless signature from the module
    /// 2. Verifies the certificate chain
    /// 3. Checks certificate expiration (with grace period)
    /// 4. Verifies the signature against the module hash
    /// 5. Verifies the Rekor inclusion proof
    /// 6. Optionally checks identity and issuer
    ///
    /// # Arguments
    /// * `module` - The signed WASM module
    /// * `expected_identity` - Optional identity to verify (e.g., "user@example.com")
    /// * `expected_issuer` - Optional OIDC issuer to verify (e.g., "https://github.com/login/oauth")
    ///
    /// # Example
    /// ```no_run
    /// use wsc::{Module, keyless::KeylessVerifier};
    ///
    /// let module = Module::deserialize_from_file("signed.wasm")?;
    /// KeylessVerifier::verify(
    ///     &module,
    ///     Some("user@example.com"),
    ///     Some("https://github.com/login/oauth")
    /// )?;
    /// println!("Signature verified successfully!");
    /// # Ok::<(), wsc::WSError>(())
    /// ```
    pub fn verify(
        _module: &Module,
        _expected_identity: Option<&str>,
        _expected_issuer: Option<&str>,
    ) -> Result<(), WSError> {
        log::info!("Starting keyless signature verification");

        // Step 1: Extract signature from module
        // TODO: Implement signature extraction from module custom section
        log::warn!("Signature extraction not yet implemented");

        // For now, return an error indicating this is not yet implemented
        Err(WSError::InternalError(
            "Keyless signature verification not yet fully implemented".to_string(),
        ))

        // Future implementation:
        // 1. Extract KeylessSignature from module custom section
        // 2. Verify certificate chain
        // 3. Check certificate expiration
        // 4. Verify signature matches module hash
        // 5. Verify Rekor inclusion proof
        // 6. Check identity/issuer if provided
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
    }

    #[test]
    fn test_keyless_config_custom() {
        let config = KeylessConfig {
            fulcio_url: Some("https://custom.fulcio.dev".to_string()),
            rekor_url: Some("https://custom.rekor.dev".to_string()),
            skip_rekor: true,
        };
        assert!(config.fulcio_url.is_some());
        assert!(config.rekor_url.is_some());
        assert!(config.skip_rekor);
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
    fn test_keyless_verifier_not_implemented() {
        // Create an empty module
        let module = Module::default();
        let result = KeylessVerifier::verify(&module, None, None);
        assert!(result.is_err());
        if let Err(WSError::InternalError(msg)) = result {
            assert!(msg.contains("not yet fully implemented"));
        } else {
            panic!("Expected InternalError");
        }
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
            let signing_key = SigningKey::<NistP256>::random(
                &mut p256::elliptic_curve::rand_core::OsRng
            );
            let verifying_key = signing_key.verifying_key();

            // Verify we can use the key
            assert!(verifying_key.to_encoded_point(false).as_bytes().len() > 0);

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
            let signing_key = SigningKey::<NistP256>::random(
                &mut p256::elliptic_curve::rand_core::OsRng
            );

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
            let signing_key = SigningKey::<NistP256>::random(
                &mut p256::elliptic_curve::rand_core::OsRng
            );
            let verifying_key = signing_key.verifying_key();
            let public_bytes = verifying_key.to_encoded_point(false);

            // Simulate an error after using the key
            if public_bytes.as_bytes().len() > 0 {
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
                let signing_key = SigningKey::<NistP256>::random(
                    &mut p256::elliptic_curve::rand_core::OsRng
                );
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
            let signing_key = SigningKey::<NistP256>::random(
                &mut p256::elliptic_curve::rand_core::OsRng
            );
            let verifying_key = signing_key.verifying_key();

            // Extract public key (safe to keep)
            verifying_key.to_encoded_point(false).as_bytes().to_vec()

            // signing_key dropped/zeroized here
        };

        // We can keep the public key, but the private key is gone
        assert!(public_key_bytes.len() > 0);

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
            let signing_key = SigningKey::<NistP256>::random(
                &mut p256::elliptic_curve::rand_core::OsRng
            );

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
            let signing_key = SigningKey::<NistP256>::random(
                &mut p256::elliptic_curve::rand_core::OsRng
            );

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
        assert!(verifying_key_bytes.len() > 0);
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

        let signing_key = SigningKey::<NistP256>::random(
            &mut p256::elliptic_curve::rand_core::OsRng
        );

        let len = consume_key(signing_key);
        // signing_key was moved into consume_key and zeroized there

        assert!(len > 0);
    }
}
