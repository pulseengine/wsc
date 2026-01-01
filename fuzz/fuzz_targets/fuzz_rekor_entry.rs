//! Fuzz target for RekorEntry JSON parsing
//!
//! This target tests the JSON deserialization of Rekor transparency log entries.
//! RekorEntry is received from remote servers and must handle malicious input.
//!
//! Security concerns:
//! - JSON injection/manipulation attacks
//! - Integer overflows in log_index
//! - Base64 decoding issues in body/signed_entry_timestamp
//! - UTF-8 validation in string fields
//! - Memory exhaustion via large JSON structures
//! - Denial of service via deeply nested JSON

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};

// Mirror the RekorEntry structure for fuzzing
// This matches wsc::signature::keyless::format::RekorEntry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorEntry {
    pub uuid: String,
    pub log_index: u64,
    pub body: String,
    pub log_id: String,
    pub inclusion_proof: Vec<u8>,
    pub signed_entry_timestamp: String,
    pub integrated_time: String,
}

fuzz_target!(|data: &[u8]| {
    // Test JSON deserialization from bytes
    if let Ok(entry) = serde_json::from_slice::<RekorEntry>(data) {
        // Try roundtrip
        if let Ok(json) = serde_json::to_vec(&entry) {
            let _ = serde_json::from_slice::<RekorEntry>(&json);
        }

        // Exercise field access (may trigger lazy parsing)
        let _ = entry.uuid.len();
        let _ = entry.log_index;
        let _ = entry.body.len();
        let _ = entry.log_id.len();
        let _ = entry.inclusion_proof.len();
        let _ = entry.signed_entry_timestamp.len();
        let _ = entry.integrated_time.len();
    }

    // Test JSON deserialization from string
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(entry) = serde_json::from_str::<RekorEntry>(s) {
            // Try roundtrip
            if let Ok(json) = serde_json::to_string(&entry) {
                let _ = serde_json::from_str::<RekorEntry>(&json);
            }
        }
    }

    // Test partial/malformed JSON structures
    // These test serde's error handling
    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct PartialEntry {
        uuid: Option<String>,
        log_index: Option<u64>,
    }

    let _ = serde_json::from_slice::<PartialEntry>(data);

    // Test deeply nested JSON (potential stack overflow)
    let _ = serde_json::from_slice::<serde_json::Value>(data);
});
