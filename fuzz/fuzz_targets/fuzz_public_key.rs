//! Fuzz target for public key parsing
//!
//! This target tests various public key parsing formats:
//! - Raw bytes (with algorithm ID prefix)
//! - PEM encoding
//! - DER encoding
//! - OpenSSH format
//! - Auto-detection (from_any)
//!
//! Security concerns:
//! - Buffer overflows in key material handling
//! - Invalid key type IDs
//! - Malformed PEM/DER structures
//! - OpenSSH format parsing edge cases
//! - Key material validation

#![no_main]

use libfuzzer_sys::fuzz_target;
use wsc::{PublicKey, SecretKey, PublicKeySet};

fuzz_target!(|data: &[u8]| {
    // Test raw bytes parsing
    if let Ok(pk) = PublicKey::from_bytes(data) {
        // Try roundtrip
        let bytes = pk.to_bytes();
        let _ = PublicKey::from_bytes(&bytes);

        // Try attaching key ID
        let pk_with_id = pk.attach_default_key_id();
        let _ = pk_with_id.key_id();
    }

    // Test DER parsing
    if let Ok(pk) = PublicKey::from_der(data) {
        let der = pk.to_der();
        let _ = PublicKey::from_der(&der);
    }

    // Test PEM parsing (if data is valid UTF-8)
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(pk) = PublicKey::from_pem(s) {
            let pem = pk.to_pem();
            let _ = PublicKey::from_pem(&pem);
        }

        // Test OpenSSH parsing
        let _ = PublicKey::from_openssh(s);

        // Test OpenSSH key set parsing
        let _ = PublicKeySet::from_openssh(s);
    }

    // Test auto-detection (tries all formats)
    if let Ok(pk) = PublicKey::from_any(data) {
        let _ = pk.to_bytes();
    }

    // Test secret key parsing (less common attack surface but still important)
    if let Ok(sk) = SecretKey::from_bytes(data) {
        let _ = sk.to_bytes();
    }

    if let Ok(sk) = SecretKey::from_der(data) {
        let _ = sk.to_der();
    }

    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(sk) = SecretKey::from_pem(s) {
            let _ = sk.to_pem();
        }

        let _ = SecretKey::from_openssh(s);
    }
});
