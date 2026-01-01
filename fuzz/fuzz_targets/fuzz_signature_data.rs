//! Fuzz target for signature data parsing
//!
//! This target tests the signature data deserialization which handles:
//! - SignatureData (specification version, content type, hash function, signed hashes)
//! - SignedHashes (array of hashes and signatures)
//! - SignatureForHashes (key ID, algorithm ID, signature bytes, certificate chain)
//!
//! Security concerns:
//! - Integer overflows in count fields
//! - Memory exhaustion via large arrays (MAX_HASHES, MAX_SIGNATURES limits)
//! - Buffer overflows when reading fixed-size hashes
//! - Varint decoding vulnerabilities
//! - Certificate chain parsing issues

#![no_main]

use libfuzzer_sys::fuzz_target;
use wsc::{SignatureData, SignedHashes, SignatureForHashes};

fuzz_target!(|data: &[u8]| {
    // Test SignatureData deserialization (top-level)
    if let Ok(sig_data) = SignatureData::deserialize(data) {
        // Try roundtrip
        if let Ok(serialized) = sig_data.serialize() {
            let _ = SignatureData::deserialize(&serialized);
        }
    }

    // Test SignedHashes deserialization (mid-level)
    if let Ok(signed_hashes) = SignedHashes::deserialize(data) {
        // Try roundtrip
        if let Ok(serialized) = signed_hashes.serialize() {
            let _ = SignedHashes::deserialize(&serialized);
        }
    }

    // Test SignatureForHashes deserialization (low-level)
    if let Ok(sig_for_hashes) = SignatureForHashes::deserialize(data) {
        // Try roundtrip
        if let Ok(serialized) = sig_for_hashes.serialize() {
            let _ = SignatureForHashes::deserialize(&serialized);
        }
    }
});
