//! Fuzz target for keyless signature format parsing
//!
//! This target tests KeylessSignature::from_bytes() which deserializes
//! untrusted binary data containing:
//! - Version and signature type bytes
//! - Varint-prefixed signature bytes
//! - Certificate chain (count + varint-prefixed PEM strings)
//! - Varint-prefixed Rekor entry JSON
//! - Varint-prefixed module hash
//!
//! Security concerns:
//! - Buffer overflows on malformed input
//! - Integer overflows in length calculations
//! - UTF-8 validation issues in certificate PEM parsing
//! - JSON parsing vulnerabilities in Rekor entry
//! - Memory exhaustion via large length prefixes
//! - Panics on unexpected input patterns

#![no_main]

use libfuzzer_sys::fuzz_target;
use wsc::keyless::KeylessSignature;

fuzz_target!(|data: &[u8]| {
    // Primary target: parse keyless signature from bytes
    // This should NEVER panic, even on completely malformed input
    let result = KeylessSignature::from_bytes(data);

    // If parsing succeeded, try to exercise additional code paths
    if let Ok(sig) = result {
        // Try to get identity (parses X.509 certificates)
        let _ = sig.get_identity();

        // Try to get issuer (parses X.509 certificates)
        let _ = sig.get_issuer();

        // Try roundtrip: serialize back and parse again
        if let Ok(serialized) = sig.to_bytes() {
            let _ = KeylessSignature::from_bytes(&serialized);
        }
    }
});
