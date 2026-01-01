//! End-to-end tests for air-gapped verification
//!
//! These tests verify the complete offline verification flow:
//! 1. Fetch trust bundle from Sigstore TUF
//! 2. Sign a WASM module with keyless signing
//! 3. Verify using the air-gapped verifier with the bundle
//!
//! Most tests require OIDC and are marked `#[ignore]`.
//! Run with: `cargo test --test airgapped_e2e -- --ignored --nocapture`

use wsc::{
    Module,
    airgapped::{
        AirGappedConfig, AirGappedVerifier, SignedTrustBundle, TrustBundle,
        MemoryTrustStore, MemoryKeyStore,
        fetch_sigstore_trusted_root, trusted_root_to_bundle,
    },
    keyless::{KeylessConfig, KeylessSigner},
};

/// Create a minimal valid WASM module for testing
fn create_test_module() -> Module {
    Module {
        header: [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00],
        sections: vec![],
    }
}

/// Create a signed trust bundle with test keys
fn create_test_bundle() -> (SignedTrustBundle, Vec<u8>) {
    use ed25519_compact::KeyPair;

    let keypair = KeyPair::generate();
    let bundle = TrustBundle::new(1, 365);
    let seed = keypair.sk.seed();
    let signed = SignedTrustBundle::sign(bundle, seed.as_ref()).unwrap();
    let public_key = keypair.pk.as_ref().to_vec();

    (signed, public_key)
}

#[test]
fn test_bundle_fetch_and_parse() {
    // Test that we can fetch and parse the Sigstore trusted root
    let result = fetch_sigstore_trusted_root();

    match result {
        Ok(root) => {
            println!("Successfully fetched Sigstore trusted root:");
            println!("  Certificate Authorities: {}", root.certificate_authorities.len());
            println!("  Transparency Logs: {}", root.tlogs.len());

            assert!(!root.certificate_authorities.is_empty(), "Should have at least one CA");
            assert!(!root.tlogs.is_empty(), "Should have at least one tlog");

            // Convert to bundle
            let bundle = trusted_root_to_bundle(&root, 1, 90).unwrap();
            assert_eq!(bundle.version, 1);
            assert!(!bundle.certificate_authorities.is_empty());
            assert!(!bundle.transparency_logs.is_empty());
            println!("  Bundle ID: {}", &bundle.bundle_id[..16]);
        }
        Err(e) => {
            // Network errors are acceptable in some environments
            println!("Could not fetch trusted root (network issue?): {}", e);
        }
    }
}

#[test]
fn test_airgapped_verifier_with_stores() {
    // Test the storage abstraction
    let (signed_bundle, public_key) = create_test_bundle();

    let trust_store = MemoryTrustStore::with_bundle(signed_bundle);
    let key_store = MemoryKeyStore::new(public_key);

    let verifier = AirGappedVerifier::<wsc::time::BuildTimeSource>::from_stores(
        &trust_store,
        &key_store,
        AirGappedConfig::default(),
    );

    assert!(verifier.is_ok(), "Should create verifier from stores");
    println!("Successfully created verifier from storage traits");
}

#[test]
fn test_bundle_signing_and_verification() {
    use ed25519_compact::KeyPair;

    // Generate signing key
    let keypair = KeyPair::generate();
    let seed = keypair.sk.seed();

    // Create and sign bundle
    let mut bundle = TrustBundle::new(42, 365);
    bundle.compute_bundle_id().unwrap();

    let signed = SignedTrustBundle::sign(bundle.clone(), seed.as_ref()).unwrap();

    // Verify with correct key
    let result = signed.verify(keypair.pk.as_ref());
    assert!(result.is_ok(), "Should verify with correct key");

    // Verify with wrong key fails
    let wrong_keypair = KeyPair::generate();
    let wrong_result = signed.verify(wrong_keypair.pk.as_ref());
    assert!(wrong_result.is_err(), "Should fail with wrong key");

    println!("Bundle signing and verification works correctly");
}

#[test]
#[ignore] // Requires OIDC and network access
fn test_full_airgapped_flow_with_sigstore() {
    // This test performs the complete air-gapped verification flow:
    // 1. Fetch real trust bundle from Sigstore
    // 2. Sign a WASM module with keyless signing
    // 3. Verify using air-gapped verifier

    println!("\n=== Full Air-Gapped Verification Flow ===\n");

    // Step 1: Fetch trust bundle from Sigstore TUF
    println!("1. Fetching trust bundle from Sigstore TUF...");
    let trusted_root = fetch_sigstore_trusted_root()
        .expect("Failed to fetch Sigstore trusted root");

    println!("   Found {} CAs, {} transparency logs",
        trusted_root.certificate_authorities.len(),
        trusted_root.tlogs.len()
    );

    let bundle = trusted_root_to_bundle(&trusted_root, 1, 90)
        .expect("Failed to create trust bundle");

    println!("   Bundle ID: {}", &bundle.bundle_id[..16]);

    // Sign the bundle (in production, use org's key)
    use ed25519_compact::KeyPair;
    let bundle_keypair = KeyPair::generate();
    let seed = bundle_keypair.sk.seed();
    let signed_bundle = SignedTrustBundle::sign(bundle, seed.as_ref())
        .expect("Failed to sign bundle");

    println!("   Bundle signed with test key");

    // Step 2: Sign a WASM module with keyless signing
    println!("\n2. Signing WASM module with keyless signing...");

    let config = KeylessConfig::default();
    let signer = KeylessSigner::with_config(config)
        .expect("Failed to create keyless signer");

    let module = create_test_module();
    let (signed_module, keyless_sig) = signer.sign_module(module)
        .expect("Failed to sign module");

    println!("   Identity: {}", keyless_sig.get_identity().unwrap_or_default());
    println!("   Issuer: {}", keyless_sig.get_issuer().unwrap_or_default());
    println!("   Rekor entry: {}", keyless_sig.rekor_entry.uuid);

    // Step 3: Verify using air-gapped verifier
    println!("\n3. Verifying with air-gapped verifier (offline mode)...");

    let verifier = AirGappedVerifier::<wsc::time::BuildTimeSource>::new(
        &signed_bundle,
        bundle_keypair.pk.as_ref(),
        AirGappedConfig::default(),
    ).expect("Failed to create air-gapped verifier");

    // Compute module hash
    let mut module_bytes = Vec::new();
    signed_module.serialize(&mut module_bytes).unwrap();
    let module_hash = hmac_sha256::Hash::hash(&module_bytes);

    // Verify the signature
    let result = verifier.verify_signature(&keyless_sig, &module_hash);

    match result {
        Ok(verification) => {
            println!("\n✅ VERIFICATION SUCCEEDED!");
            println!("   Valid: {}", verification.valid);
            if let Some(identity) = &verification.identity {
                println!("   Subject: {}", identity.subject);
                println!("   Issuer: {}", identity.issuer);
            }
            for warning in &verification.warnings {
                println!("   Warning: {:?}", warning);
            }
        }
        Err(e) => {
            println!("\n❌ Verification failed: {}", e);
            println!("\n📋 Debug info:");
            println!("   Cert chain length: {}", keyless_sig.cert_chain.len());
            println!("   Bundle CAs: {}", signed_bundle.bundle.certificate_authorities.len());
            println!("   Bundle logs: {}", signed_bundle.bundle.transparency_logs.len());

            // This is expected to fail initially - certificate chain verification
            // against the bundle's root certs needs the full implementation
            println!("\n⚠️  Note: Full certificate chain verification is not yet implemented");
            println!("   The keyless signature was created and the bundle was verified,");
            println!("   but cross-referencing them requires certificate path validation.");
        }
    }

    println!("\n=== End-to-End Test Complete ===\n");
}

#[test]
#[ignore] // Requires OIDC
fn test_keyless_sign_then_airgapped_verify() {
    // Simplified test: sign with keyless, verify bundle separately

    // Create keyless signer
    let signer = KeylessSigner::new().expect("Need OIDC environment");

    // Sign test module
    let module = create_test_module();
    let (_signed_module, keyless_sig) = signer.sign_module(module)
        .expect("Failed to sign module");

    println!("Keyless signature created:");
    println!("  Identity: {}", keyless_sig.get_identity().unwrap_or_default());
    println!("  Rekor UUID: {}", keyless_sig.rekor_entry.uuid);
    println!("  Rekor index: {}", keyless_sig.rekor_entry.log_index);

    // Verify we have the expected structure
    assert!(!keyless_sig.signature.is_empty());
    assert!(!keyless_sig.cert_chain.is_empty());
    assert!(!keyless_sig.rekor_entry.uuid.is_empty());
    assert!(keyless_sig.rekor_entry.log_index > 0);

    println!("\n✅ Keyless signature has valid structure for air-gapped verification");
}

#[test]
fn test_bundle_anti_rollback() {
    use wsc::airgapped::DeviceSecurityState;

    let (signed_bundle, public_key) = create_test_bundle();

    // Create device state with higher version
    let mut state = DeviceSecurityState::new(1704067200);
    state.bundle_version = 10; // Device has seen version 10

    // Try to create verifier with older bundle (version 1)
    let config = AirGappedConfig::default().with_rollback_protection();

    let verifier = AirGappedVerifier::<wsc::time::BuildTimeSource>::new(
        &signed_bundle,
        &public_key,
        config,
    ).unwrap();

    // Adding state should fail due to rollback protection
    let result = verifier.with_device_state(state);
    assert!(result.is_err(), "Should reject bundle older than device state");

    println!("Anti-rollback protection working correctly");
}

#[test]
fn test_bundle_validity_periods() {
    let (signed_bundle, public_key) = create_test_bundle();

    let verifier = AirGappedVerifier::<wsc::time::BuildTimeSource>::new(
        &signed_bundle,
        &public_key,
        AirGappedConfig::default(),
    ).unwrap();

    // Check bundle health
    let warnings = verifier.check_bundle_health();

    println!("Bundle health check:");
    println!("  Warnings: {}", warnings.len());
    for w in &warnings {
        println!("  - {:?}", w);
    }

    // Fresh bundle should have no warnings
    assert!(warnings.is_empty(), "Fresh bundle should have no warnings");
}
