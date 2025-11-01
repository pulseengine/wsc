/// Rekor transparency log client for keyless signing
///
/// This module provides integration with the Rekor transparency log,
/// which provides a tamper-proof record of signatures and certificates.
///
/// # Example
///
/// ```no_run
/// use wasmsign2::keyless::{RekorClient, FulcioCertificate};
///
/// // Create a Rekor client
/// let client = RekorClient::new();
///
/// // Create a mock certificate (in real use, get from Fulcio)
/// let certificate = FulcioCertificate {
///     cert_chain: vec!["-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".to_string()],
///     leaf_cert: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".to_string(),
///     public_key: vec![0u8; 32],
/// };
///
/// // Upload an entry to the transparency log
/// let artifact_hash = vec![0u8; 32]; // SHA256 hash of artifact
/// let signature = vec![0u8; 64]; // Ed25519 signature
///
/// match client.upload_entry(&artifact_hash, &signature, &certificate) {
///     Ok(entry) => {
///         println!("Entry uploaded successfully!");
///         println!("UUID: {}", entry.uuid);
///         println!("Log Index: {}", entry.log_index);
///         println!("Integrated Time: {}", entry.integrated_time);
///     }
///     Err(e) => eprintln!("Failed to upload entry: {}", e),
/// }
/// ```

use crate::error::WSError;
use crate::signature::keyless::fulcio::FulcioCertificate;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Rekor log entry returned from the transparency log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorEntry {
    /// Log entry UUID
    pub uuid: String,
    /// Log index
    pub log_index: u64,
    /// Base64-encoded entry body (needed for SET verification)
    pub body: String,
    /// Log ID (needed for SET verification)
    pub log_id: String,
    /// Inclusion proof (for verification) - JSON serialized
    pub inclusion_proof: Vec<u8>,
    /// Signed Entry Timestamp - base64-encoded signature
    pub signed_entry_timestamp: String,
    /// Integrated time timestamp (RFC3339)
    pub integrated_time: String,
}

/// Request payload for Rekor log entry upload
#[derive(Debug, Serialize)]
struct RekorUploadRequest {
    kind: String,
    #[serde(rename = "apiVersion")]
    api_version: String,
    spec: RekorSpec,
}

#[derive(Debug, Serialize)]
struct RekorSpec {
    signature: RekorSignature,
    data: RekorData,
}

#[derive(Debug, Serialize)]
struct RekorSignature {
    content: String,
    #[serde(rename = "publicKey")]
    public_key: RekorPublicKey,
}

#[derive(Debug, Serialize)]
struct RekorPublicKey {
    content: String,
}

#[derive(Debug, Serialize)]
struct RekorData {
    hash: RekorHash,
}

#[derive(Debug, Serialize)]
struct RekorHash {
    algorithm: String,
    value: String,
}

/// Response from Rekor log entry upload
/// The response is a map where the key is the UUID and value contains the entry details
#[derive(Debug, Deserialize)]
struct RekorUploadResponse {
    #[serde(flatten)]
    entries: HashMap<String, RekorEntryResponse>,
}

#[derive(Debug, Deserialize)]
struct RekorEntryResponse {
    #[serde(rename = "logIndex")]
    log_index: u64,
    #[allow(dead_code)]
    body: String, // Base64-encoded body (not currently used but part of API response)
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    #[serde(rename = "logID")]
    #[allow(dead_code)]
    log_id: String, // Log ID (not currently used but part of API response)
    verification: Option<RekorVerification>,
}

#[derive(Debug, Deserialize)]
struct RekorVerification {
    #[serde(rename = "inclusionProof")]
    inclusion_proof: Option<RekorInclusionProof>,
    #[serde(rename = "signedEntryTimestamp")]
    signed_entry_timestamp: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RekorInclusionProof {
    hashes: Vec<String>,
    #[serde(rename = "logIndex")]
    log_index: u64,
    #[serde(rename = "rootHash")]
    root_hash: String,
    #[serde(rename = "treeSize")]
    tree_size: u64,
}

/// Rekor client for transparency log operations
pub struct RekorClient {
    /// Rekor server URL (default: https://rekor.sigstore.dev)
    base_url: String,
    #[cfg(not(target_os = "wasi"))]
    client: ureq::Agent,
}

impl RekorClient {
    /// Create client with default Rekor server
    pub fn new() -> Self {
        Self::with_url("https://rekor.sigstore.dev".to_string())
    }

    /// Create client with custom Rekor server
    pub fn with_url(base_url: String) -> Self {
        #[cfg(not(target_os = "wasi"))]
        {
            // Configure agent to return Response for all status codes (not Error)
            // so we can read error response bodies
            let agent = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into();

            Self {
                base_url,
                client: agent,
            }
        }

        #[cfg(target_os = "wasi")]
        {
            Self { base_url }
        }
    }

    /// Upload signature to Rekor transparency log
    ///
    /// # Arguments
    /// * `artifact_hash` - SHA256 hash of signed artifact (32 bytes)
    /// * `signature` - Signature bytes (DER-encoded for ECDSA)
    /// * `certificate` - Certificate from Fulcio
    ///
    /// # Returns
    /// * `RekorEntry` - The transparency log entry
    pub fn upload_entry(
        &self,
        artifact_hash: &[u8],
        signature: &[u8],
        certificate: &FulcioCertificate,
    ) -> Result<RekorEntry, WSError> {
        // Validate hash length
        if artifact_hash.len() != 32 {
            return Err(WSError::RekorError(
                "Artifact hash must be 32 bytes (SHA-256 for ECDSA)".to_string(),
            ));
        }

        // Convert hash to hex string
        let hash_hex = artifact_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        // Encode signature and certificate chain as base64
        let signature_b64 = BASE64.encode(signature);

        // Join certificate chain into single PEM block
        let cert_chain_pem = certificate.cert_chain.join("\n");
        let cert_b64 = BASE64.encode(cert_chain_pem.as_bytes());

        // Build request payload
        let request = RekorUploadRequest {
            kind: "hashedrekord".to_string(),
            api_version: "0.0.1".to_string(),
            spec: RekorSpec {
                signature: RekorSignature {
                    content: signature_b64,
                    public_key: RekorPublicKey {
                        content: cert_b64,
                    },
                },
                data: RekorData {
                    hash: RekorHash {
                        // ECDSA signatures use SHA-256 per Rekor hashedrekord spec
                        algorithm: "sha256".to_string(),
                        value: hash_hex,
                    },
                },
            },
        };

        // Send request (different implementations for native vs WASI)
        #[cfg(not(target_os = "wasi"))]
        {
            self.upload_entry_native(request)
        }

        #[cfg(target_os = "wasi")]
        {
            self.upload_entry_wasi(request)
        }
    }

    /// Native implementation using ureq
    #[cfg(not(target_os = "wasi"))]
    fn upload_entry_native(
        &self,
        request: RekorUploadRequest,
    ) -> Result<RekorEntry, WSError> {
        let url = format!("{}/api/v1/log/entries", self.base_url);

        let json_request = serde_json::to_string(&request)
            .map_err(|e| WSError::RekorError(format!("Failed to serialize request: {}", e)))?;

        // Agent configured with http_status_as_error(false), so we always get Ok(Response)
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .send(json_request.as_bytes())
            .map_err(|e| WSError::RekorError(format!("Failed to upload entry: {}", e)))?;

        // Check status code
        let status = response.status();
        if status != 201 {
            let error_text = response
                .into_body()
                .read_to_string()
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(WSError::RekorError(format!(
                "Upload failed with status {}: {}",
                status,
                error_text
            )));
        }

        // Parse response
        let body = response.into_body().read_to_string().map_err(|e| {
            WSError::RekorError(format!("Failed to read response body: {}", e))
        })?;

        let response_data: RekorUploadResponse = serde_json::from_str(&body)
            .map_err(|e| WSError::RekorError(format!("Failed to parse response: {}", e)))?;

        // Extract entry (should be exactly one entry in the map)
        if response_data.entries.is_empty() {
            return Err(WSError::RekorError(
                "No entry returned in response".to_string(),
            ));
        }

        let (uuid, entry_data) = response_data
            .entries
            .into_iter()
            .next()
            .ok_or_else(|| WSError::RekorError("Empty response from Rekor".to_string()))?;

        // Extract verification data
        let verification = entry_data.verification.unwrap_or_else(|| RekorVerification {
            inclusion_proof: None,
            signed_entry_timestamp: None,
        });

        // Extract inclusion proof if available
        let inclusion_proof = verification
            .inclusion_proof
            .map(|proof| {
                // Serialize the inclusion proof to JSON bytes
                serde_json::to_vec(&proof).unwrap_or_default()
            })
            .unwrap_or_default();

        // Extract SET if available
        let signed_entry_timestamp = verification
            .signed_entry_timestamp
            .unwrap_or_default();

        // Convert integrated_time (Unix timestamp) to RFC3339
        let integrated_time = format_timestamp(entry_data.integrated_time);

        Ok(RekorEntry {
            uuid,
            log_index: entry_data.log_index,
            body: entry_data.body,
            log_id: entry_data.log_id,
            inclusion_proof,
            signed_entry_timestamp,
            integrated_time,
        })
    }

    /// WASI implementation using wasi::http
    #[cfg(target_os = "wasi")]
    fn upload_entry_wasi(
        &self,
        request: RekorUploadRequest,
    ) -> Result<RekorEntry, WSError> {
        use wasi::http::outgoing_handler;
        use wasi::http::types::{
            Fields, Method, OutgoingBody, OutgoingRequest, Scheme,
        };
        use wasi::io::streams::StreamError;

        let url = format!("{}/api/v1/log/entries", self.base_url);

        // Parse URL
        let url_parts: Vec<&str> = url.split("://").collect();
        if url_parts.len() != 2 {
            return Err(WSError::RekorError("Invalid URL format".to_string()));
        }

        let scheme = if url_parts[0] == "https" {
            Scheme::Https
        } else {
            Scheme::Http
        };

        let remaining: Vec<&str> = url_parts[1].splitn(2, '/').collect();
        let authority = remaining[0].to_string();
        let path_and_query = if remaining.len() > 1 {
            format!("/{}", remaining[1])
        } else {
            "/".to_string()
        };

        // Create request
        let headers = Fields::new();
        headers.set(
            &"Content-Type".to_string(),
            &[b"application/json".to_vec()],
        );

        let outgoing_request = OutgoingRequest::new(headers);
        outgoing_request.set_scheme(Some(&scheme));
        outgoing_request.set_authority(Some(&authority));
        outgoing_request.set_path_with_query(Some(&path_and_query));
        outgoing_request.set_method(&Method::Post);

        // Serialize request body
        let request_json = serde_json::to_vec(&request)
            .map_err(|e| WSError::RekorError(format!("Failed to serialize request: {}", e)))?;

        let outgoing_body = outgoing_request.body()
            .map_err(|_| WSError::RekorError("Failed to get request body".to_string()))?;
        {
            let outgoing_stream = outgoing_body.write()
                .map_err(|_| WSError::RekorError("Failed to write request body".to_string()))?;
            outgoing_stream.blocking_write_and_flush(&request_json)
                .map_err(|e| WSError::RekorError(format!("Failed to send request: {:?}", e)))?;
        }
        OutgoingBody::finish(outgoing_body, None)
            .map_err(|_| WSError::RekorError("Failed to finish request body".to_string()))?;

        // Send request
        let future_response = outgoing_handler::handle(outgoing_request, None)
            .map_err(|_| WSError::RekorError("Failed to send HTTP request".to_string()))?;
        let incoming_response = future_response
            .get()
            .ok_or_else(|| WSError::RekorError("No response received".to_string()))?
            .map_err(|_| WSError::RekorError("Request failed".to_string()))??;

        // Check status
        let status = incoming_response.status();
        if status != 201 {
            return Err(WSError::RekorError(format!(
                "Upload failed with status {}",
                status
            )));
        }

        // Read response body
        let incoming_body = incoming_response
            .consume()
            .map_err(|_| WSError::RekorError("Failed to get response body".to_string()))?;
        let incoming_stream = incoming_body.stream()
            .map_err(|_| WSError::RekorError("Failed to get response stream".to_string()))?;

        let mut response_bytes = Vec::new();
        loop {
            match incoming_stream.blocking_read(4096) {
                Ok(chunk) => {
                    if chunk.is_empty() {
                        break;
                    }
                    response_bytes.extend_from_slice(&chunk);
                }
                Err(StreamError::Closed) => break,
                Err(e) => {
                    return Err(WSError::RekorError(format!("Stream error: {:?}", e)));
                }
            }
        }

        // Parse response
        let response_data: RekorUploadResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| WSError::RekorError(format!("Failed to parse response: {}", e)))?;

        // Extract entry
        if response_data.entries.is_empty() {
            return Err(WSError::RekorError(
                "No entry returned in response".to_string(),
            ));
        }

        let (uuid, entry_data) = response_data
            .entries
            .into_iter()
            .next()
            .ok_or_else(|| WSError::RekorError("Empty response from Rekor".to_string()))?;

        // Extract verification data
        let verification = entry_data.verification.unwrap_or_else(|| RekorVerification {
            inclusion_proof: None,
            signed_entry_timestamp: None,
        });

        // Extract inclusion proof if available
        let inclusion_proof = verification
            .inclusion_proof
            .map(|proof| serde_json::to_vec(&proof).unwrap_or_default())
            .unwrap_or_default();

        // Extract SET if available
        let signed_entry_timestamp = verification
            .signed_entry_timestamp
            .unwrap_or_default();

        // Convert integrated_time to RFC3339
        let integrated_time = format_timestamp(entry_data.integrated_time);

        Ok(RekorEntry {
            uuid,
            log_index: entry_data.log_index,
            body: entry_data.body,
            log_id: entry_data.log_id,
            inclusion_proof,
            signed_entry_timestamp,
            integrated_time,
        })
    }

    /// Verify inclusion proof and SET for a Rekor entry
    ///
    /// This performs full cryptographic verification:
    /// 1. Signed Entry Timestamp (SET) verification using ECDSA P-256
    /// 2. Merkle tree inclusion proof verification (RFC 6962)
    ///
    /// # Arguments
    /// * `entry` - The Rekor log entry to verify
    ///
    /// # Returns
    /// `Ok(true)` if verification succeeds, `Err(WSError)` otherwise
    ///
    /// # Security
    /// This ensures that:
    /// - Rekor accepted and timestamped the entry (SET signature)
    /// - The entry exists in the transparency log (inclusion proof)
    /// - The transparency log is cryptographically sound (Merkle tree)
    pub fn verify_inclusion(&self, entry: &RekorEntry) -> Result<bool, WSError> {
        use super::rekor_verifier::RekorKeyring;

        // Load Rekor public keys from trusted root
        let keyring = RekorKeyring::from_embedded_trust_root()
            .map_err(|e| WSError::RekorError(format!("Failed to load Rekor keys: {}", e)))?;

        // Perform full verification (SET + inclusion proof)
        keyring.verify_entry(entry)?;

        Ok(true)
    }
}

impl Default for RekorClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Format Unix timestamp to RFC3339 string
fn format_timestamp(timestamp: i64) -> String {
    use time::{format_description::well_known::Rfc3339, OffsetDateTime};

    match OffsetDateTime::from_unix_timestamp(timestamp) {
        Ok(dt) => dt.format(&Rfc3339).unwrap_or_else(|_| timestamp.to_string()),
        Err(_) => timestamp.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rekor_client_new() {
        let client = RekorClient::new();
        assert_eq!(client.base_url, "https://rekor.sigstore.dev");
    }

    #[test]
    fn test_rekor_client_with_url() {
        let custom_url = "https://custom.rekor.server".to_string();
        let client = RekorClient::with_url(custom_url.clone());
        assert_eq!(client.base_url, custom_url);
    }

    #[test]
    fn test_format_timestamp() {
        // Test a known timestamp: 2024-01-01 00:00:00 UTC
        let timestamp = 1704067200i64;
        let formatted = format_timestamp(timestamp);
        assert!(formatted.contains("2024"));
    }

    #[test]
    fn test_rekor_entry_creation() {
        let entry = RekorEntry {
            uuid: "test-uuid-123".to_string(),
            log_index: 42,
            body: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            log_id: "test-log-id".to_string(),
            inclusion_proof: vec![1, 2, 3, 4],
            signed_entry_timestamp: "c2lnbmF0dXJl".to_string(),
            integrated_time: "2024-01-01T00:00:00Z".to_string(),
        };

        assert_eq!(entry.uuid, "test-uuid-123");
        assert_eq!(entry.log_index, 42);
        assert_eq!(entry.body, "eyJ0ZXN0IjoidmFsdWUifQ==");
        assert_eq!(entry.log_id, "test-log-id");
        assert_eq!(entry.inclusion_proof, vec![1, 2, 3, 4]);
        assert_eq!(entry.signed_entry_timestamp, "c2lnbmF0dXJl");
        assert_eq!(entry.integrated_time, "2024-01-01T00:00:00Z");
    }

    #[test]
    fn test_upload_entry_invalid_hash_length() {
        let client = RekorClient::new();

        // Create stub certificate
        let cert = FulcioCertificate {
            cert_chain: vec!["-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string()],
            leaf_cert: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            public_key: vec![0u8; 65],
        };

        // Test with invalid hash length (not 32 bytes for SHA-256)
        let invalid_hash = vec![0u8; 64];  // Wrong: SHA-512 size instead of SHA-256
        let signature = vec![0u8; 64];

        let result = client.upload_entry(&invalid_hash, &signature, &cert);
        assert!(result.is_err());

        if let Err(WSError::RekorError(msg)) = result {
            assert!(msg.contains("32 bytes"));
        } else {
            panic!("Expected RekorError");
        }
    }

    #[test]
    fn test_verify_inclusion_rejects_invalid() {
        let client = RekorClient::new();
        let entry = RekorEntry {
            uuid: "test-uuid".to_string(),
            log_index: 1,
            body: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            log_id: "test-log-id".to_string(),
            inclusion_proof: vec![],
            signed_entry_timestamp: String::new(),
            integrated_time: "2024-01-01T00:00:00Z".to_string(),
        };

        // Real verification should reject this invalid entry
        let result = client.verify_inclusion(&entry);
        assert!(result.is_err(), "Should reject entry with no SET");
    }

    #[test]
    fn test_rekor_upload_request_serialization() {
        let request = RekorUploadRequest {
            kind: "hashedrekord".to_string(),
            api_version: "0.0.1".to_string(),
            spec: RekorSpec {
                signature: RekorSignature {
                    content: "c2lnbmF0dXJl".to_string(), // "signature" in base64
                    public_key: RekorPublicKey {
                        content: "Y2VydGlmaWNhdGU=".to_string(), // "certificate" in base64
                    },
                },
                data: RekorData {
                    hash: RekorHash {
                        algorithm: "sha256".to_string(),
                        value: "abcdef1234567890".to_string(),
                    },
                },
            },
        };

        let json = serde_json::to_string(&request).unwrap();

        // Verify JSON contains expected fields
        assert!(json.contains("hashedrekord"));
        assert!(json.contains("0.0.1"));
        assert!(json.contains("sha256"));
        assert!(json.contains("c2lnbmF0dXJl"));
    }

    #[test]
    fn test_rekor_upload_response_deserialization() {
        let json = r#"{
            "24296fb24b8ad77a123456789abcdef": {
                "logIndex": 12345,
                "body": "eyJhcGlWZXJzaW9uIjoiMC4wLjEifQ==",
                "integratedTime": 1704067200,
                "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
                "verification": {
                    "inclusionProof": {
                        "hashes": ["hash1", "hash2"],
                        "logIndex": 12345,
                        "rootHash": "root",
                        "treeSize": 100000
                    }
                }
            }
        }"#;

        let response: RekorUploadResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.entries.len(), 1);

        let (uuid, entry) = response.entries.into_iter().next().unwrap();
        assert!(uuid.starts_with("24296fb24b8ad77a"));
        assert_eq!(entry.log_index, 12345);
        assert_eq!(entry.integrated_time, 1704067200);
        assert!(entry.verification.is_some());
    }

    #[test]
    fn test_mock_rekor_entry_flow() {
        // This test demonstrates the expected flow with mock data
        let client = RekorClient::new();

        // Create mock certificate
        let cert = FulcioCertificate {
            cert_chain: vec![
                "-----BEGIN CERTIFICATE-----\nMIIBkTCCATegAwIBAgIUTest\n-----END CERTIFICATE-----".to_string()
            ],
            leaf_cert: "-----BEGIN CERTIFICATE-----\nMIIBkTCCATegAwIBAgIUTest\n-----END CERTIFICATE-----".to_string(),
            public_key: vec![0u8; 65],  // ECDSA P-256 uncompressed public key
        };

        // Create valid SHA256 hash (32 bytes)
        let artifact_hash = vec![0u8; 32];
        let signature = vec![0u8; 64];  // ECDSA signature (DER-encoded, approximate size)

        // Note: This will fail because we don't have a real Rekor server
        // But it demonstrates the API usage
        let result = client.upload_entry(&artifact_hash, &signature, &cert);

        // In a real integration test, we would mock the HTTP response
        // For now, we just verify the error is a Rekor error (connection failure)
        assert!(result.is_err());
    }
}
