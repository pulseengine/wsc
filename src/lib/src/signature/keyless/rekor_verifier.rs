//! Rekor Transparency Log Verification
//!
//! This module implements cryptographic verification of Rekor log entries:
//! 1. Signed Entry Timestamp (SET) verification
//! 2. Merkle tree inclusion proof verification
//!
//! # Security Model
//!
//! Rekor entries are verified using:
//! - **SET (Signed Entry Timestamp)**: ECDSA P-256 signature over entry metadata
//! - **Inclusion Proof**: RFC 6962 Merkle tree proof
//! - **Trust Anchors**: Rekor public keys from Sigstore TUF repository
//!
//! The SET proves that Rekor accepted and timestamped the entry.
//! The inclusion proof proves that the entry exists in the transparency log.

use crate::error::WSError;
use crate::signature::keyless::{merkle, RekorEntry};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Trusted root configuration for Rekor transparency logs
#[derive(Debug, Serialize, Deserialize)]
struct TrustedRoot {
    tlogs: Vec<TransparencyLog>,
}

/// Transparency log configuration from TUF
#[derive(Debug, Serialize, Deserialize)]
struct TransparencyLog {
    #[serde(rename = "baseUrl")]
    base_url: String,
    #[serde(rename = "hashAlgorithm")]
    hash_algorithm: String,
    #[serde(rename = "publicKey")]
    public_key: PublicKeyInfo,
    #[serde(rename = "logId")]
    log_id: LogId,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicKeyInfo {
    #[serde(rename = "rawBytes")]
    raw_bytes: String, // Base64-encoded
    #[serde(rename = "keyDetails")]
    key_details: String,
    #[serde(rename = "validFor")]
    valid_for: ValidFor,
}

#[derive(Debug, Serialize, Deserialize)]
struct LogId {
    #[serde(rename = "keyId")]
    key_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidFor {
    start: String,
}

/// Rekor inclusion proof structure (deserialized from JSON)
#[derive(Debug, Deserialize)]
pub struct InclusionProof {
    pub hashes: Vec<String>,
    #[serde(rename = "logIndex")]
    pub log_index: u64,
    #[serde(rename = "rootHash")]
    pub root_hash: String,
    #[serde(rename = "treeSize")]
    pub tree_size: u64,
}

/// Pool of Rekor public keys for verification
pub struct RekorKeyring {
    /// ECDSA P-256 verifying keys indexed by log ID
    keys: Vec<(String, VerifyingKey)>,
}

impl RekorKeyring {
    /// Load Rekor public keys from embedded trusted_root.json
    pub fn from_embedded_trust_root() -> Result<Self, WSError> {
        let trusted_root_json = include_str!("trust_root/trusted_root.json");
        let trusted_root: TrustedRoot = serde_json::from_str(trusted_root_json)
            .map_err(|e| WSError::RekorError(format!("Failed to parse trusted_root.json: {}", e)))?;

        Self::from_trusted_root(trusted_root)
    }

    /// Create keyring from TrustedRoot structure
    fn from_trusted_root(trusted_root: TrustedRoot) -> Result<Self, WSError> {
        let mut keys = Vec::new();

        for tlog in trusted_root.tlogs {
            // Verify this is an ECDSA P-256 key
            if !tlog.public_key.key_details.contains("ECDSA_P256") {
                log::warn!(
                    "Skipping non-ECDSA-P256 key: {}",
                    tlog.public_key.key_details
                );
                continue;
            }

            // Decode the public key from base64
            let key_bytes = BASE64
                .decode(&tlog.public_key.raw_bytes)
                .map_err(|e| WSError::RekorError(format!("Failed to decode public key: {}", e)))?;

            // Parse as SPKI-encoded ECDSA P-256 key
            let verifying_key = VerifyingKey::from_sec1_bytes(&key_bytes)
                .or_else(|_| {
                    // Try parsing as DER/SPKI format
                    spki::SubjectPublicKeyInfoRef::try_from(key_bytes.as_slice())
                        .map_err(|e| WSError::RekorError(format!("Failed to parse SPKI: {}", e)))
                        .and_then(|spki| {
                            VerifyingKey::try_from(spki)
                                .map_err(|e| WSError::RekorError(format!("Failed to parse key: {}", e)))
                        })
                })
                .map_err(|e| WSError::RekorError(format!("Failed to parse ECDSA key: {}", e)))?;

            // Convert log ID from base64 (in TUF) to hex (as used by Rekor API)
            let key_id_bytes = BASE64
                .decode(&tlog.log_id.key_id)
                .map_err(|e| WSError::RekorError(format!("Failed to decode log ID: {}", e)))?;
            let key_id = hex::encode(&key_id_bytes);

            log::debug!("Loaded Rekor public key for log ID: {}", key_id);
            keys.push((key_id, verifying_key));
        }

        if keys.is_empty() {
            return Err(WSError::RekorError(
                "No Rekor public keys found in trusted_root.json".to_string(),
            ));
        }

        Ok(Self { keys })
    }

    /// Verify a Signed Entry Timestamp (SET)
    ///
    /// # Arguments
    /// * `entry` - The Rekor log entry to verify
    ///
    /// # Returns
    /// `Ok(())` if the SET signature is valid, `Err(WSError)` otherwise
    ///
    /// # SET Signature Algorithm (RFC 8785)
    ///
    /// Per Rekor's OpenAPI spec, the SET is computed as:
    /// ```text
    /// 1. Remove the "verification" object from the JSON document
    /// 2. Canonicalize the remaining JSON using RFC 8785
    /// 3. Sign the canonicalized JSON: ECDSA_P256_Sign(SHA256(canonicalized_json))
    /// ```
    ///
    /// The entry JSON structure (before removing verification):
    /// ```json
    /// {
    ///   "body": "base64...",
    ///   "integratedTime": 1610452407,
    ///   "logID": "hex...",
    ///   "logIndex": 0
    /// }
    /// ```
    pub fn verify_set(&self, entry: &RekorEntry) -> Result<(), WSError> {
        if entry.signed_entry_timestamp.is_empty() {
            return Err(WSError::RekorError(
                "Missing signed entry timestamp".to_string(),
            ));
        }

        // Decode SET signature from base64
        let signature_bytes = BASE64
            .decode(&entry.signed_entry_timestamp)
            .map_err(|e| WSError::RekorError(format!("Failed to decode SET signature: {}", e)))?;

        // Parse as ECDSA signature (DER format)
        let signature = Signature::from_der(&signature_bytes)
            .or_else(|_| {
                // Try as raw 64-byte signature (r || s)
                if signature_bytes.len() == 64 {
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(&signature_bytes);
                    Signature::from_bytes(&arr.into())
                        .map_err(|e| WSError::RekorError(format!("Failed to parse signature: {}", e)))
                } else {
                    Err(WSError::RekorError(format!(
                        "Invalid signature format: {} bytes",
                        signature_bytes.len()
                    )))
                }
            })?;

        // Find the matching public key for this log
        let verifying_key = self
            .keys
            .iter()
            .find(|(key_id, _)| key_id == &entry.log_id)
            .map(|(_, key)| key)
            .ok_or_else(|| {
                WSError::RekorError(format!(
                    "No public key found for log ID: {}",
                    entry.log_id
                ))
            })?;

        // Parse integrated_time from RFC3339 to Unix timestamp
        let integrated_time = chrono::DateTime::parse_from_rfc3339(&entry.integrated_time)
            .map_err(|e| WSError::RekorError(format!("Failed to parse integrated_time: {}", e)))?;
        let integrated_time_unix = integrated_time.timestamp();

        // Construct the JSON object that was signed (without "verification" field)
        // This matches Rekor's API response structure
        let entry_json = serde_json::json!({
            "body": entry.body,
            "integratedTime": integrated_time_unix,
            "logID": entry.log_id,
            "logIndex": entry.log_index
        });

        // Canonicalize using RFC 8785 (JCS)
        let canonical_json = serde_jcs::to_vec(&entry_json)
            .map_err(|e| WSError::RekorError(format!("Failed to canonicalize JSON: {}", e)))?;

        #[cfg(test)]
        println!("🔍 Canonical JSON for SET: {}", String::from_utf8_lossy(&canonical_json));

        // Hash the canonical JSON
        let mut hasher = Sha256::new();
        hasher.update(&canonical_json);
        let message_hash = hasher.finalize();

        // Verify the signature
        verifying_key
            .verify(&message_hash, &signature)
            .map_err(|e| {
                WSError::RekorError(format!("SET signature verification failed: {}", e))
            })?;

        log::debug!("SET signature verified successfully");
        Ok(())
    }

    /// Verify a Merkle tree inclusion proof
    ///
    /// # Arguments
    /// * `entry` - The Rekor log entry containing the inclusion proof
    ///
    /// # Returns
    /// `Ok(())` if the inclusion proof is valid, `Err(WSError)` otherwise
    pub fn verify_inclusion_proof(&self, entry: &RekorEntry) -> Result<(), WSError> {
        if entry.inclusion_proof.is_empty() {
            return Err(WSError::RekorError(
                "Missing inclusion proof".to_string(),
            ));
        }

        // Deserialize the inclusion proof from JSON
        let proof: InclusionProof = serde_json::from_slice(&entry.inclusion_proof)
            .map_err(|e| WSError::RekorError(format!("Failed to parse inclusion proof: {}", e)))?;

        // Decode the body (base64-encoded entry data)
        let body_bytes = BASE64
            .decode(&entry.body)
            .map_err(|e| WSError::RekorError(format!("Failed to decode body: {}", e)))?;

        // Compute leaf hash (RFC 6962: SHA-256(0x00 || decoded_body))
        // Rekor's Merkle tree is built over the decoded entry bodies
        let leaf_hash = merkle::compute_leaf_hash(&body_bytes);

        // Decode proof hashes from hex
        let proof_hashes: Result<Vec<[u8; 32]>, _> = proof
            .hashes
            .iter()
            .map(|h| {
                let bytes = hex::decode(h)
                    .map_err(|e| WSError::RekorError(format!("Failed to decode proof hash: {}", e)))?;
                if bytes.len() != 32 {
                    return Err(WSError::RekorError(format!(
                        "Invalid proof hash length: {}",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(arr)
            })
            .collect();
        let proof_hashes = proof_hashes?;

        // Decode expected root hash from hex
        let expected_root = hex::decode(&proof.root_hash)
            .map_err(|e| WSError::RekorError(format!("Failed to decode root hash: {}", e)))?;
        if expected_root.len() != 32 {
            return Err(WSError::RekorError(format!(
                "Invalid root hash length: {}",
                expected_root.len()
            )));
        }
        let mut root_arr = [0u8; 32];
        root_arr.copy_from_slice(&expected_root);

        // Verify the inclusion proof using RFC 6962 algorithm
        merkle::verify_inclusion_proof(
            proof.log_index,
            proof.tree_size,
            &leaf_hash,
            &proof_hashes,
            &root_arr,
        )?;

        log::debug!("Merkle inclusion proof verified successfully");
        Ok(())
    }

    /// Verify both SET and inclusion proof for a Rekor entry
    ///
    /// This is the main entry point for full Rekor verification.
    pub fn verify_entry(&self, entry: &RekorEntry) -> Result<(), WSError> {
        // Step 1: Verify Signed Entry Timestamp (proves Rekor accepted the entry)
        self.verify_set(entry)?;

        // Step 2: Verify Merkle inclusion proof (proves entry is in the log)
        self.verify_inclusion_proof(entry)?;

        log::info!("Rekor entry fully verified (SET + inclusion proof)");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_rekor_keys() {
        let keyring = RekorKeyring::from_embedded_trust_root();
        assert!(keyring.is_ok(), "Failed to load Rekor keys: {:?}", keyring.err());

        let keyring = keyring.unwrap();
        assert!(!keyring.keys.is_empty(), "No Rekor keys loaded");

        println!("Loaded {} Rekor public keys", keyring.keys.len());
        for (log_id, _) in &keyring.keys {
            println!("  - Log ID: {}", log_id);
        }
    }

    #[test]
    fn test_trusted_root_json_structure() {
        let trusted_root_json = include_str!("trust_root/trusted_root.json");
        let result: Result<TrustedRoot, _> = serde_json::from_str(trusted_root_json);

        assert!(result.is_ok(), "Failed to parse trusted_root.json: {:?}", result.err());

        let trusted_root = result.unwrap();
        assert!(!trusted_root.tlogs.is_empty(), "No transparency logs found");

        for tlog in &trusted_root.tlogs {
            println!("Transparency Log:");
            println!("  Base URL: {}", tlog.base_url);
            println!("  Hash Algorithm: {}", tlog.hash_algorithm);
            println!("  Key Details: {}", tlog.public_key.key_details);
            println!("  Log ID: {}", tlog.log_id.key_id);
        }
    }

    /// **CRITICAL TEST**: Validate against REAL production Rekor data
    ///
    /// This test uses an actual Rekor entry from production (logIndex 0).
    /// It validates that our SET and inclusion proof verification works
    /// with real data from rekor.sigstore.dev.
    ///
    /// Entry UUID: b08416d417acdb0610d4a030d8f697f9d0a718024681a00fa0b9ba67072a38b5
    /// Fetched from: https://rekor.sigstore.dev/api/v1/log/entries/...
    #[test]
    fn test_verify_real_production_rekor_entry() {
        use super::super::RekorEntry;

        // Real production entry from Rekor (logIndex 0, the very first entry!)
        let real_entry = RekorEntry {
            uuid: "362f8ecba72f4326b08416d417acdb0610d4a030d8f697f9d0a718024681a00fa0b9ba67072a38b5".to_string(),
            log_index: 0,
            body: "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJzcGVjIjp7ImRhdGEiOnsiaGFzaCI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6IjQ1YzdiMTFmY2JmMDdkZWMxNjk0YWRlY2Q4YzViODU3NzBhMTJhNmM4ZGZkY2YyNTgwYTJkYjBjNDdjMzE3NzkifX0sInNpZ25hdHVyZSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVIxQWdVMGxIVGtGVVZWSkZMUzB0TFMwS0NtbFJTRXRDUVVGQ1EwRkJNRVpwUlVWalowTlZXRWMzT0dGa2FqWm9SMVZLU25KbVFtOUtNRFJ3U0c5R1FXd3JPRFpTZDFkSVIzaHZZVmMxYTJNd1FuY0tZMjA1TUdJeU5YUlpWMnh6VEcxT2RtSlJRVXREVWtGdGREaEhaMjVVYVd0bGFtTklReTg1ZVhsSFJWQm9Na1FyVFc1T1VqaEpPSGN3YzJaWFEyaGpOZ3B3UjBGUmIxTTJjV3N2YzJaREx6bEhka1kwVDBNM1VrbDVOazkzVEhJdmJIaDVSVnBpVDFBeWJtZFphbWd2Y3pWTGFrdDRhRnA1UVhCM2QyY3hNMHh0Q21OaVlYcEhibGhqTTBVM05rbzFOVXh2VkdaM2IxSmhPV1oxY0VndlRUWklTVFUyVmtaTGQyNTFLMEZpVFU1WE1YTXJSRTAwTjNJM2FUVnVTVTQyU1ZnS09XdE5jRVJsTTBJNVdGUlZWVXhtWmk5NVRsVjJNRmgwV0ZVclZrRm1PRzVrUmpGM01URTNXVlpYZUdZNFZHNVZMMGhYZGxnM05GVlNVVkJPSzNONWRRcDVjVXN2VGs4eFNERkxhRUpXVkhwalNWbGtOVWcyYTBwMU16QXdhbWRyUkhsd2VYbHhVWEJrTDNCS1dWWjNabVZaT0daRFQyRmxRM0JtU1ZCcVMxRXZDalJsYmtOelFXVkNaMHR6UVhkbVNXSnZjamhYYVVVNE5rdHZRVTVaY1ZKUFlWYzNkWEZwVGl0V1VHRmtZbGRXWlU0MllrMXdVa2xrUlhFNEswNUxVVWNLYkdWd1UwTlNjV0pyVm1jMFZrdEhUMUJuUWpOb05WZGlXVGxWTVU4eFJsWkVibGg1ZERkclYyUkZVRVZhYWtKWUsxWTBSR0YzYzJoMlRtVTFURWw1Y1FwSU5XaEtNVkZPUVVaa01GVlRkSEZMVVhRNFJWVmFMMmRCZEZGcFdGTkhZbmhOTVVGRGIxbE1PVWhpYkV0WE5XSXJhMm92YjI1TFoyaGxhMFp2UTI5QkNtWm9UWGRTVW5GU05XY3ZWRk12VUdNeUwzcDBkMWxVU1hWb2NGRlJaazFZZW1sVWJUWTBaejBLUFRVdlYya0tMUzB0TFMxRlRrUWdVRWRRSUZOSlIwNUJWRlZTUlMwdExTMHQiLCJmb3JtYXQiOiJwZ3AiLCJwdWJsaWNLZXkiOnsiY29udGVudCI6IkxTMHRMUzFDUlVkSlRpQlFSMUFnVUZWQ1RFbERJRXRGV1NCQ1RFOURTeTB0TFMwdENncDRjMFJPUWtZclkwbE5NRUpFUVVOaE9FYzNVa1F5ZGpOdGFYZE5kSGhXWVZwcE0wcENWblZsVmtGeFNFdEROR1ZMYjAxVE5VaE5RMUp2SzBoYVZsSkJDamN3V0cxelZIQllNVm94WjFwUmRYVkRNRWRFV1RJMmFFSm9aV3BCY1ROb2VESnlkall2T0hFNU1FSjJWMGRJT1hSV1pVZHdUREZ6WVVsdE5USm5SVklLV0hsV1oyZDZOV3RCUXpCVE5uWk5iamRrY2pKbGRFSnJWMWRRSzA5cU1EVlRNREpaV2tKVVdXZDRjRTlpZVdWalZWTmpjVXRPVkdwemJGcFJRa2d5WkFwVFNIVnJNMjh5V2pkb1RUUTVWVEJzTjNwaVYzYzBiMGxVSzJ4QlVtTnpZV3BSVkhkWGFteHBZVkJFTDBoU2FsUXlibEpQYUVsb2FYUmxaQzkzWjNsNkNubGtTWEUxWlRaek1UaFdUR05VTnpWeFYyNXlXbGhPVUZkR2QyWXlOVkpZV1ROMWRHdFhLMGRYTlc1UlpVNDRNRkV5YTFKRloydDRSbk0xUVdRMVYxb0tka1UzZERndmFIZzFlbTF6YkZvMGRHWkdOSE5wTTFGYVpVbFJRbUZqV1dKM2VFMVFVMFJtT1c5R1IzaGtSMFpVT0RnNWQwcE1SMmRYYlhJeFZHdFFUUXBqVGpBMmQzaEJVa2QwZUU0d2VqWXhSa3BVYVdwTVYxSmlhbGN6ZFc1Sk9XaGpVV05WYkU0dlVTc3hObTkwU0hCbFMxWm5ORzlYTURCRGNuWlhUMFEyQ25GclRHTk5SRFE1ZVZWRU9HWlRSMElyVWtWdWFVSmhPRGxET1d0UlZUUlRTMlJuYzB4TUwxRXJTa3NyVTNrNVMyMUpSSEp0TVdFMFJHWlFNWEJ6Wm1VS1RHcGhjbnB6VmxwbVMxVklabmRqUVVWUlJVRkJZekJwVkVoV2NscFRRa2xoVnpWclkzbEJPR0pIYUhCaWJWSjZVVWhDZVdJelVuWmliVEZvWVZkM2RRcFpNamwwVUhOTVFrWkJVVlJCVVdkQlVHaFphRUpJU1VGc1JuaDFMMGR1V1N0dlVteERVMkV6ZDJGRFpFOUxValpDVVVwbWJrTkVUa0ZvYzBSQ1VXdEVDbmR0WTBGQ1VYTktRMEZqUTBKb1ZVdERVV2RNUVdkUlYwRm5UVUpCYURSQ1FXaGxRVUZCYjBwRlEyRXpkMkZEWkU5TFVqWmFNV3RNTHpGSlN6QjJaR1VLV2xnMWNqVlRaV0pPZUZSSlRsTkJRWFpaYTNKTFVubEtOV1kzYkU5Tk9XZE1SMGwxWXpKR2IwNVZibXBXVVZRd2NrbEhPVEF4T1dnME9IQkRlVGt4WmdwWWFrUkVVazFaT1dkNlJsZFhRMmRIYmxob01XaFhTVE5OTjBKS1JqWlpSVFoxTmtSWVIzTjJkVlZ3UjNKT1pWcEJSelpyYTJGNlFYVkJibTVXTUd0RENqQTRlbTlTY2tGYVEzWnNjR0ZhY25sa09HbDBZaXR5Vml0UlMzQTNRWGN5YkVGSlNERmxObVIzVFRSU1RFWnFkbVpyT0V4S1dIaHFTa0Z2VUcxM05td0tUSGN4T0dNM2IxYzJVa3hQT1ZGWVVUaGxUVFp5TW5aSVNIQnRNRlIxWkhaYWVXRm1UblZETXpKSFJHeE5XVFIxTUZZeFJHSTRUSE41YlZCelFXaDFRUW95U25vMEwwdFFjVFoxUzNkSmRHMVdTelJ3Ym1SbVJVUjFOa1F4Vkc5dlJGbFlhWEIwV1dGbVpIWlZNek53VlZGNGQwaHZabFJVWmtVMWVscDNNbEJsQ214SU0yNWFaSE5uU0ZoSFVIaEtURXhOY1U5d1Z6UkRMMk5OTmxwUlZtZFpVM1JXY2pCdWRsVTJOaXRSYWxGMmMydFZXbEl3Tm1Sa1JYcHVRbkJIU25NK2RIQnRhamxCWlM5SFVsazRSVTV1VGprdk1rZG1SWFZ5ZEhvelpFdE9WVnB2YWsxNU1UVXphbU5ITUZVeGVucG9NVEUxVjBvM2REaDNTRUoxTkZNMGNBb3daMFVyVWtGeGVYUkJZMGxhUkdReVRsTk9jbm80Vm5JNVJrVTVlQ3RtWVhRNVJWSnNZbTVrUVVKRk5XbFdPSE5MTUN0R1lXNVhkMmRqTjBGNlVWSm1DbTVEUkU1QlVYZEJkRUp2ZEdobVkxSjZjak40Y2pOUU9YQTNVVU5OZDB0MWFXOXVkazFEYlRoWFozZE9VelJEY0doeGJ6Vk9UM0l5YVUxcWEweFFNRW9LYjIxblNreFdXRFZPSzJKeWRqaDVORWc0Y2xsUWQwdENNVFp2TDJoQk9FbGlSMkp3V1hsdE0wWmplV3RVZDJOaVYySjBVRlJNUlhSa1ExVlFURmxVUkFwT1F6Vk1SMHB3WnpObE9EWlpabEYwUVU0MkwwMXVXbmxaVDIxc1JIZ3lWMGQwZEV4a2JYTkJVMGRXZFhnMlFWWktjVWwySzNnd05sVkxTa1Z0U3pOMENtcHNSVlpMZVdjeE1sSkZlbmxsTlVsVU5uRkZVMGR3VDNwdk1sbHNWMVZ4U1ZSM0wwRmhVRkV5V25oVllYaDJXVVp2VlU5amQyZGpaRzVJYTJkemFFa0tUMjQ1YUM5T1NGVnRVRE15VjFGMmNXdFJUWFZWWVZCSlRsSnpRemd6UzNaVVJFZHNlV1pUU0ZaR2VrMWhOR2hFVFdoRlkxaDZOR0ZqYVc1a05WZFVaUXA2ZVV4bldtaFBZamRqVG1WRGVEUjRZM0owVUVJMlZUZENVaTlHVmt4NlRFSnNRWHAxZW1wcFJXaFpkMHB2TTBGUFRYRkdiMUkxYlVGeGFHeDFkRTVQQ25OemVXOW1ZbkZVWjBkaVUweGthbUpZVUM5aFJYUm5lakpOVmpsdUwyOWpNVk5DT0VobFdrOHZNVGRLZVdkdWVuSjFTVXQ1S3k5c1QxZFBlblFyYWxZS1ZrWndWbmxvTVhWbE9HeEdOM2x0UzFJMGRITnNLMmxKVm1KeGJsQjJjRTFvVEU5SlFuRllSbTR5WjAxRGEwZHZTa3g1TjA5SWJ6SlhRVVZLUjJ4ME13cFRkM0JpY21wcU1VRkNSVUpCUVVoRGQxQjNSVWRCUlVsQlExbFhTVkZTZVVGS1VtTmlkbmh3TWxCeFJWcFJhMjEwT0VkbmJsUnBhMlZuVlVOWU5YZG5DbnBSU1dKRVFWVktRVGhLYmtGQlFVdERVa0Z0ZERoSFoyNVVhV3RsYVc1cFJFRkRSVUZtYTFweEx6UlNjREpoVGtFMFpHSnZTamRWUmxoRVQyRlNhMVlLT1UxTGIwVmFSbkZVVFU1dmRrUk1OWGhvVFd4bmJGQlFkUzlzSzJSb1ZHZDRaR1ZLT1VWV1NHOWxlblJpT0RrMlZTOXdUM1ZDVW5OdU9WWjBWelJaTHdwcVpXbFhOMFY1VGxoQlpDOVBjblp1Um1KNEt6ZHBXRXh4ZFhCYVNrcEdWR2t2YWpsU2FGWlpUbk50YkRkelpXSlVVR1ZDYmtkRVFUa3hjV0pETkhoSUNuQlJWa1JEZFdwNE5qbFdlRTgxUlRGTVUyOW9RMDByVHk4MWRreENiVGhwTVc4dmJtSkdiV0o1TjFaRGVVdGxVa1JtYUhSbU9XNURPRFJ4YzBVNVIzRUtWVGN2VEZOcGF6bGlabmhOVjJKd2NUaDVhMjUwYlZNellUQnplbU0wWWxaR2NHVjZRbkJ0VG1Jd1FWWmpRaXRVYlRsblYyMUZlbWhwVEhNMlJrdEJUZ3BKYm5GT2RWaDFRa3c1VUVOaFl6Y3JiVlVyWXpKdFFtZEhUMUpIWkRGa1drOHpVa000T1hwR00zaENRbGx1UTA5bE5XTkJUVVpzWXpGWVIzTnNiSE5KQ21SNlpISmtXSFppVGtKNkwybzNNWEIxVGpodlJsbHRMMWhpVm1OcFpVOHdWR1pSYVVSalZIUTRTMmxwVWpsVVFVUTVMMUExT1ROU1RXeE1UMGRUT0hBS2FIWktZbWxHYjFwbVdFaGpiSE5hUmtodE9FUlJVV0U1TkVsYWQxUkNPRzAwWjBKV01FMHlXRk4yWkVodk16QnNjM0ZxZEZwaFdtbFRjbEpvTkhKemFBcHVNVFJ3WWtGaFZHUmhTMFZRWTNaMGRXWmlWWFZYTUVscVdXUXlhM0JKVkM5MFp6MEtQV2hhV0ZVS0xTMHRMUzFGVGtRZ1VFZFFJRkJWUWt4SlF5QkxSVmtnUWt4UFEwc3RMUzB0TFE9PSJ9fX0sImtpbmQiOiJyZWtvcmQifQ==".to_string(),
            log_id: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d".to_string(),
            inclusion_proof: serde_json::to_vec(&serde_json::json!({
                "hashes": [
                    "073970a07c978b7a9ff15b69fe15d87dfb58fd5756086e3d1fb671c2d0bd95c0",
                    "766ae2c918bbc083a6cce41f6ff3a3cf1a8153b86f594303ce16ded44c99647b"
                ],
                "logIndex": 0,
                "rootHash": "4d006aa46efcb607dd51d900b1213754c50cc9251c3405c6c2561d9d6a2f3239",
                "treeSize": 4163431
            })).unwrap(),
            // Real SET from production API (from verification.signedEntryTimestamp)
            signed_entry_timestamp: "MEYCIQDpQB2Ww4a+Rb0Vm95ZC/PqwNbCCC+ROWKr/vh4yLBXYQIhAIboLjkjAjVF6ucr3U5G3mIOUIZZoG6G1rahErvz+Pn8".to_string(),
            integrated_time: "2021-01-12T11:53:27Z".to_string(),
        };

        println!("\n🔐 Testing with REAL production Rekor entry (logIndex 0)");
        println!("UUID: {}", real_entry.uuid);
        println!("Log ID: {}", real_entry.log_id);
        println!("Integrated Time: {}", real_entry.integrated_time);

        // Load the keyring
        let keyring = RekorKeyring::from_embedded_trust_root()
            .expect("Failed to load Rekor keyring");

        // **THE CRITICAL MOMENT**: Verify against real production data
        println!("\n⏳ Verifying SET signature...");
        let set_result = keyring.verify_set(&real_entry);

        match &set_result {
            Ok(()) => println!("✅ SET signature VERIFIED against real production data!"),
            Err(e) => {
                println!("❌ SET verification FAILED: {}", e);
                println!("\n📋 Debug Info:");
                println!("  This failure indicates our SET message format is WRONG.");
                println!("  We need to adjust how we construct the message in verify_set().");
            }
        }

        println!("\n⏳ Verifying Merkle inclusion proof...");
        let inclusion_result = keyring.verify_inclusion_proof(&real_entry);

        match &inclusion_result {
            Ok(()) => println!("✅ Inclusion proof VERIFIED against real production data!"),
            Err(e) => {
                println!("❌ Inclusion proof verification FAILED: {}", e);
                println!("\n📋 Debug Info:");
                println!("  This failure indicates our leaf hash or proof algorithm is WRONG.");
            }
        }

        // Both must pass for the test to succeed
        set_result.expect("SET verification must pass with real production data");
        inclusion_result.expect("Inclusion proof verification must pass with real production data");

        println!("\n🎉 SUCCESS! Our implementation works with REAL Rekor production data!");
    }
}
