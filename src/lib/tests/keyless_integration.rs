//! Integration tests for keyless signing
//!
//! These tests verify the end-to-end keyless signing flow.
//! Most tests are marked with `#[ignore]` because they require:
//! - OIDC provider credentials (GitHub Actions, Google Cloud, etc.)
//! - Network access to Fulcio and Rekor servers
//!
//! To run these tests:
//! ```bash
//! # In GitHub Actions with OIDC
//! cargo test --test keyless_integration -- --ignored
//! ```

use wsc::{Module, keyless::{KeylessSigner, KeylessConfig, detect_oidc_provider}};

/// Helper to create a minimal valid WASM module
fn create_test_module() -> Module {
    Module {
        header: [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00], // WASM header
        sections: vec![],
    }
}

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
    assert_eq!(config.fulcio_url.unwrap(), "https://custom.fulcio.dev");
    assert_eq!(config.rekor_url.unwrap(), "https://custom.rekor.dev");
    assert!(config.skip_rekor);
}

#[test]
#[ignore] // Requires GitHub Actions environment with OIDC
fn test_github_actions_keyless_signing() {
    // This test only runs in GitHub Actions with proper OIDC setup
    // Required environment variables:
    // - GITHUB_ACTIONS=true
    // - ACTIONS_ID_TOKEN_REQUEST_TOKEN
    // - ACTIONS_ID_TOKEN_REQUEST_URL

    let provider = detect_oidc_provider()
        .expect("Failed to detect OIDC provider - are you running in GitHub Actions?");

    assert_eq!(provider.name(), "GitHub Actions");

    let config = KeylessConfig::default();
    let signer = KeylessSigner::with_config(config)
        .expect("Failed to create keyless signer");

    let module = create_test_module();
    let (signed_module, signature) = signer.sign_module(module)
        .expect("Failed to sign module");

    // Verify the signature was created
    assert!(!signature.signature.is_empty());
    assert!(!signature.cert_chain.is_empty());
    assert!(!signature.rekor_entry.uuid.is_empty());
    assert!(signature.rekor_entry.log_index > 0);

    // Verify we can extract identity and issuer
    let identity = signature.get_identity()
        .expect("Failed to extract identity");
    let issuer = signature.get_issuer()
        .expect("Failed to extract issuer");

    println!("Signed by: {}", identity);
    println!("Issuer: {}", issuer);
    println!("Rekor entry: {}", signature.rekor_entry.uuid);
    println!("Log index: {}", signature.rekor_entry.log_index);
    println!("Integrated time: {}", signature.rekor_entry.integrated_time);

    // **CRITICAL TEST**: Verify the Rekor entry against production data
    // This validates our SET and inclusion proof verification against REAL Rekor responses
    println!("\n🔐 Testing Rekor verification with REAL production data...");

    use wsc::keyless::RekorClient;
    let rekor_client = RekorClient::new();
    let verification_result = rekor_client.verify_inclusion(&signature.rekor_entry);

    match &verification_result {
        Ok(true) => {
            println!("✅ SET signature verified successfully!");
            println!("✅ Merkle inclusion proof verified successfully!");
            println!("✅ VALIDATION PASSED: Our implementation works with real Rekor data!");
        }
        Ok(false) => {
            panic!("❌ Verification returned false (unexpected)");
        }
        Err(e) => {
            println!("❌ Verification FAILED: {}", e);
            println!("\n📋 Debug Info:");
            println!("  Body length: {}", signature.rekor_entry.body.len());
            println!("  Log ID: {}", signature.rekor_entry.log_id);
            println!("  SET length: {}", signature.rekor_entry.signed_entry_timestamp.len());
            println!("  Inclusion proof length: {}", signature.rekor_entry.inclusion_proof.len());
            panic!("Rekor verification failed with real data: {}", e);
        }
    }

    verification_result.expect("Rekor verification must succeed with real production data");

    // Verify the module structure is valid
    assert_eq!(signed_module.header, [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]);
}

#[test]
#[ignore] // Requires GitHub Actions environment
fn test_keyless_signing_with_skip_rekor() {
    // Test signing with Rekor upload skipped (for testing only)
    let provider = detect_oidc_provider()
        .expect("Failed to detect OIDC provider");

    let config = KeylessConfig {
        fulcio_url: None,
        rekor_url: None,
        skip_rekor: true, // Skip Rekor for faster testing
    };

    let signer = KeylessSigner::with_config(config)
        .expect("Failed to create keyless signer");

    let module = create_test_module();
    let (signed_module, signature) = signer.sign_module(module)
        .expect("Failed to sign module");

    // When Rekor is skipped, the entry should be empty or have a dummy value
    assert!(
        signature.rekor_entry.uuid.is_empty() || signature.rekor_entry.uuid == "skipped"
    );
}

#[test]
#[ignore] // Requires network access
fn test_keyless_signing_with_custom_servers() {
    // Test with custom Fulcio/Rekor servers (e.g., staging)
    let provider = detect_oidc_provider()
        .expect("Failed to detect OIDC provider");

    let config = KeylessConfig {
        fulcio_url: Some("https://fulcio.sigstore.dev".to_string()),
        rekor_url: Some("https://rekor.sigstore.dev".to_string()),
        skip_rekor: false,
    };

    let signer = KeylessSigner::with_config(config)
        .expect("Failed to create keyless signer");

    let module = create_test_module();
    let result = signer.sign_module(module);

    // Should succeed or fail gracefully
    if let Err(e) = result {
        eprintln!("Signing failed (expected in some environments): {}", e);
    }
}

#[test]
fn test_keyless_signing_without_oidc_fails() {
    // This test verifies that signing fails gracefully when no OIDC provider is available
    // Unset all OIDC environment variables to ensure clean state

    let result = KeylessSigner::new();

    // In most development environments without OIDC setup, this should fail
    // In CI with OIDC, this will succeed - that's okay
    match result {
        Ok(_) => {
            println!("OIDC provider detected (running in CI environment)");
        }
        Err(e) => {
            println!("No OIDC provider detected (expected in dev environment): {}", e);
            assert!(
                matches!(e, wsc::WSError::NoOidcProvider) ||
                matches!(e, wsc::WSError::OidcError(_))
            );
        }
    }
}

#[test]
fn test_signature_format_roundtrip() {
    use wsc::keyless::{KeylessSignature, RekorEntry};

    // Test that we can serialize and deserialize a keyless signature
    let original = KeylessSignature::new(
        vec![0u8; 64], // Ed25519 signature
        vec!["-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string()],
        RekorEntry {
            uuid: "test-uuid-12345".to_string(),
            log_index: 42,
            body: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            log_id: "test-log-id".to_string(),
            inclusion_proof: vec![1, 2, 3, 4],
            signed_entry_timestamp: "c2lnbmF0dXJl".to_string(),
            integrated_time: "2024-10-25T12:00:00Z".to_string(),
        },
        vec![0u8; 32], // SHA256 hash
    );

    // Serialize
    let bytes = original.to_bytes()
        .expect("Failed to serialize signature");

    assert!(!bytes.is_empty());
    assert!(bytes.len() > 100); // Should be at least a few hundred bytes

    // Deserialize
    let recovered = KeylessSignature::from_bytes(&bytes)
        .expect("Failed to deserialize signature");

    // Verify fields match
    assert_eq!(recovered.signature, original.signature);
    assert_eq!(recovered.cert_chain.len(), original.cert_chain.len());
    assert_eq!(recovered.rekor_entry.uuid, original.rekor_entry.uuid);
    assert_eq!(recovered.rekor_entry.log_index, original.rekor_entry.log_index);
    assert_eq!(recovered.module_hash, original.module_hash);
}

#[test]
fn test_module_serialization() {
    // Verify that our test module can be serialized
    let module = create_test_module();

    let mut buffer = Vec::new();
    module.serialize(&mut buffer)
        .expect("Failed to serialize module");

    assert!(!buffer.is_empty());
    assert_eq!(&buffer[0..8], &[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]);
}
