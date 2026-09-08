//! Sigstore bundle format for signature interoperability.
//!
//! Provides types matching the Sigstore bundle protobuf spec
//! for portable signature exchange without protobuf dependencies.
//!
//! The Sigstore bundle format (v0.3) is the standard exchange format for
//! Sigstore signatures. It packages the signature, verification material
//! (certificate chain + transparency log entries), and message digest into
//! a single JSON document that can be verified by `cosign verify-blob-attestation`
//! or `sigstore-rs`.
//!
//! See: <https://github.com/sigstore/protobuf-specs>

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

use crate::signature::keyless::KeylessSignature;

/// Current media type for Sigstore bundles.
pub const BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

/// Top-level Sigstore bundle.
///
/// Matches the Sigstore bundle protobuf schema for JSON serialization.
/// Contains all material needed to verify a signature offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigstoreBundle {
    /// Media type identifier (always `application/vnd.dev.sigstore.bundle.v0.3+json`).
    pub media_type: String,

    /// Verification material (certificates + log entries).
    pub verification_material: VerificationMaterial,

    /// The actual message signature.
    pub message_signature: MessageSignature,
}

/// Verification material bundled with the signature.
///
/// Contains the certificate chain used for signing and any transparency
/// log entries that provide non-repudiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMaterial {
    /// X.509 certificate chain from Fulcio.
    pub x509_certificate_chain: CertificateChain,

    /// Transparency log entries from Rekor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tlog_entries: Vec<TransparencyLogEntry>,
}

/// A list of DER-encoded X.509 certificates.
///
/// The leaf certificate is first, followed by intermediates, then the root.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateChain {
    /// Base64-encoded DER certificates.
    pub certificates: Vec<Certificate>,
}

/// A single certificate in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Certificate {
    /// Base64-encoded DER content of the certificate.
    pub raw_bytes: String,
}

/// The signature over the message/artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSignature {
    /// The digest of the signed content.
    pub message_digest: MessageDigest,

    /// Base64-encoded signature bytes.
    pub signature: String,
}

/// A content digest with algorithm identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageDigest {
    /// Hash algorithm (e.g., "SHA2_256").
    pub algorithm: String,

    /// Hex-encoded digest value.
    pub digest: String,
}

/// A Rekor transparency log entry in bundle format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransparencyLogEntry {
    /// Log index in the transparency log.
    pub log_index: String,

    /// Log ID (identifier for the log instance).
    pub log_id: LogId,

    /// The canonicalized entry body, base64-encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonicalized_body: Option<String>,

    /// Integrated time as a Unix timestamp string.
    pub integrated_time: String,

    /// Inclusion proof for the Merkle tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<InclusionProof>,

    /// The inclusion promise, carrying the Signed Entry Timestamp (SET).
    ///
    /// Per the Sigstore protobuf spec (and as real cosign output confirms), the
    /// SET lives at `inclusionPromise.signedEntryTimestamp` — NOT as a
    /// top-level field on the entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusion_promise: Option<InclusionPromise>,

    /// Legacy top-level SET emitted by wsc <= 0.11.0.
    ///
    /// Non-conformant: no other Sigstore implementation reads it. Accepted on
    /// *deserialize* so bundles wsc emitted before this fix still round-trip,
    /// but never serialized. Prefer [`Self::signed_entry_timestamp`].
    #[serde(
        rename = "signedEntryTimestamp",
        skip_serializing,
        default,
        alias = "signed_entry_timestamp"
    )]
    pub legacy_signed_entry_timestamp: Option<String>,
}

impl TransparencyLogEntry {
    /// The Signed Entry Timestamp, from the spec location, falling back to the
    /// legacy top-level field for bundles wsc emitted before the fix.
    pub fn signed_entry_timestamp(&self) -> Option<&str> {
        self.inclusion_promise
            .as_ref()
            .map(|p| p.signed_entry_timestamp.as_str())
            .or(self.legacy_signed_entry_timestamp.as_deref())
    }
}

/// The inclusion promise: Rekor's signed statement that an entry was accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionPromise {
    /// The Signed Entry Timestamp (SET), base64-encoded.
    pub signed_entry_timestamp: String,
}

/// Log instance identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogId {
    /// The key ID of the log, **base64-encoded**.
    ///
    /// The Sigstore protobuf spec types this as a `bytes` field, and protobuf's
    /// JSON mapping encodes `bytes` as base64 — which is what real cosign
    /// emits. wsc's `RekorEntry::log_id` holds the same value hex-encoded (the
    /// form the Rekor REST API uses), so the emitter transcodes hex -> base64.
    pub key_id: String,
}

/// Merkle tree inclusion proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProof {
    /// Log index for the proof.
    pub log_index: String,

    /// Root hash of the Merkle tree.
    pub root_hash: String,

    /// Tree size at the time of the proof.
    pub tree_size: String,

    /// Hashes forming the inclusion proof path.
    pub hashes: Vec<String>,
}

impl SigstoreBundle {
    /// Convert a wsc `KeylessSignature` to the Sigstore bundle format.
    ///
    /// This enables interoperability with the broader Sigstore ecosystem.
    /// The resulting bundle can be verified by `cosign verify-blob --bundle`.
    ///
    /// # Arguments
    ///
    /// * `sig` - A keyless signature from wsc's internal format
    ///
    /// # Returns
    ///
    /// A `SigstoreBundle` containing all verification material.
    pub fn from_keyless_signature(sig: &KeylessSignature) -> Self {
        // Convert PEM certificate chain to base64-encoded DER.
        let certificates: Vec<Certificate> = sig
            .cert_chain
            .iter()
            .map(|pem_str| {
                let der_bytes = pem_to_der(pem_str);
                Certificate {
                    raw_bytes: BASE64.encode(&der_bytes),
                }
            })
            .collect();

        // Build transparency log entry from Rekor entry.
        let tlog_entry = build_tlog_entry(&sig.rekor_entry);

        // Build message digest from module hash.
        let digest_hex = sig
            .module_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        SigstoreBundle {
            media_type: BUNDLE_MEDIA_TYPE.to_string(),
            verification_material: VerificationMaterial {
                x509_certificate_chain: CertificateChain { certificates },
                tlog_entries: vec![tlog_entry],
            },
            message_signature: MessageSignature {
                message_digest: MessageDigest {
                    algorithm: "SHA2_256".to_string(),
                    digest: digest_hex,
                },
                signature: BASE64.encode(&sig.signature),
            },
        }
    }

    /// Serialize the bundle to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(self)
    }

    /// Deserialize a bundle from JSON bytes.
    pub fn from_json(json: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(json)
    }
}

/// Build a `TransparencyLogEntry` from a wsc `RekorEntry`.
fn build_tlog_entry(
    rekor: &crate::signature::keyless::rekor::RekorEntry,
) -> TransparencyLogEntry {
    // Parse inclusion proof from the serialized bytes if available.
    let inclusion_proof = if rekor.inclusion_proof.is_empty() {
        None
    } else {
        parse_inclusion_proof(&rekor.inclusion_proof)
    };

    // Convert integrated_time from RFC3339 to Unix timestamp string.
    let integrated_time_str = chrono::DateTime::parse_from_rfc3339(&rekor.integrated_time)
        .map(|dt| dt.timestamp().to_string())
        .unwrap_or_else(|_| rekor.integrated_time.clone());

    TransparencyLogEntry {
        log_index: rekor.log_index.to_string(),
        log_id: LogId {
            // `RekorEntry::log_id` is hex (the Rekor REST form); the bundle
            // spec's `LogId.key_id` is a protobuf `bytes` field, so its JSON
            // mapping is base64 — what real cosign emits. Transcode. If the
            // value is not valid hex it is not a Rekor log id we can transcode,
            // so pass it through unchanged rather than silently emitting junk.
            key_id: match hex::decode(&rekor.log_id) {
                Ok(bytes) => BASE64.encode(&bytes),
                Err(_) => rekor.log_id.clone(),
            },
        },
        canonicalized_body: if rekor.body.is_empty() {
            None
        } else {
            Some(rekor.body.clone())
        },
        integrated_time: integrated_time_str,
        inclusion_proof,
        inclusion_promise: if rekor.signed_entry_timestamp.is_empty() {
            None
        } else {
            Some(InclusionPromise {
                signed_entry_timestamp: rekor.signed_entry_timestamp.clone(),
            })
        },
        // Never emitted; present only to accept pre-fix wsc bundles on read.
        legacy_signed_entry_timestamp: None,
    }
}

/// Parse the JSON-serialized inclusion proof bytes into an `InclusionProof`.
fn parse_inclusion_proof(bytes: &[u8]) -> Option<InclusionProof> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawProof {
        hashes: Vec<String>,
        log_index: u64,
        root_hash: String,
        tree_size: u64,
    }

    let raw: RawProof = serde_json::from_slice(bytes).ok()?;

    Some(InclusionProof {
        log_index: raw.log_index.to_string(),
        root_hash: raw.root_hash,
        tree_size: raw.tree_size.to_string(),
        hashes: raw.hashes,
    })
}

/// Extract DER bytes from a PEM-encoded certificate string.
///
/// Strips PEM headers/footers and decodes the base64 content.
/// If decoding fails, returns the raw PEM bytes as a fallback.
fn pem_to_der(pem_str: &str) -> Vec<u8> {
    // Strip PEM headers and whitespace
    let b64: String = pem_str
        .lines()
        .filter(|line| {
            !line.starts_with("-----BEGIN") && !line.starts_with("-----END") && !line.is_empty()
        })
        .collect::<Vec<&str>>()
        .join("");

    // Decode base64
    BASE64.decode(&b64).unwrap_or_else(|_| pem_str.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::keyless::rekor::RekorEntry;

    fn create_test_rekor_entry() -> RekorEntry {
        RekorEntry {
            uuid: "test-uuid-1234".to_string(),
            log_index: 42,
            body: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            log_id: "c0d23d6ad406973f".to_string(),
            inclusion_proof: serde_json::to_vec(&serde_json::json!({
                "hashes": ["aabbcc", "ddeeff"],
                "logIndex": 42,
                "rootHash": "112233",
                "treeSize": 1000
            }))
            .unwrap(),
            signed_entry_timestamp: "c2lnbmF0dXJl".to_string(),
            integrated_time: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    fn create_test_keyless_signature() -> KeylessSignature {
        KeylessSignature::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            vec![
                "-----BEGIN CERTIFICATE-----\nTUlJQmtUQ0NBVGVnQXdJQkFnSVVUZXN0\n-----END CERTIFICATE-----".to_string(),
                "-----BEGIN CERTIFICATE-----\nTUlJQmtUQ0NBVGVnQXdJQkFnSVVSb290\n-----END CERTIFICATE-----".to_string(),
            ],
            create_test_rekor_entry(),
            vec![0xde, 0xad, 0xbe, 0xef],
        )
    }

    #[test]
    fn test_bundle_media_type() {
        assert_eq!(
            BUNDLE_MEDIA_TYPE,
            "application/vnd.dev.sigstore.bundle.v0.3+json"
        );
    }

    #[test]
    fn test_from_keyless_signature() {
        let sig = create_test_keyless_signature();
        let bundle = SigstoreBundle::from_keyless_signature(&sig);

        assert_eq!(bundle.media_type, BUNDLE_MEDIA_TYPE);
        assert_eq!(
            bundle.verification_material.x509_certificate_chain.certificates.len(),
            2
        );
        assert_eq!(bundle.verification_material.tlog_entries.len(), 1);

        // Check message signature
        let expected_sig_b64 = BASE64.encode(&sig.signature);
        assert_eq!(bundle.message_signature.signature, expected_sig_b64);

        // Check digest
        assert_eq!(bundle.message_signature.message_digest.algorithm, "SHA2_256");
        assert_eq!(bundle.message_signature.message_digest.digest, "deadbeef");
    }

    #[test]
    fn test_tlog_entry_conversion() {
        let rekor = create_test_rekor_entry();
        let tlog = build_tlog_entry(&rekor);

        assert_eq!(tlog.log_index, "42");
        // The spec's LogId.key_id is a protobuf `bytes` field -> base64 in JSON
        // (what real cosign emits). RekorEntry::log_id holds it as hex, so the
        // emitter transcodes: hex "c0d23d6ad406973f" -> base64 "wNI9atQGlz8=".
        assert_eq!(
            tlog.log_id.key_id,
            BASE64.encode(hex::decode("c0d23d6ad406973f").unwrap())
        );
        assert_eq!(tlog.integrated_time, "1704067200");
        assert!(tlog.canonicalized_body.is_some());
        // SET lives under inclusionPromise per the spec, not at the top level.
        assert!(tlog.inclusion_promise.is_some());
        assert!(tlog.signed_entry_timestamp().is_some());
        assert!(tlog.legacy_signed_entry_timestamp.is_none());

        // Check inclusion proof was parsed
        let proof = tlog.inclusion_proof.unwrap();
        assert_eq!(proof.log_index, "42");
        assert_eq!(proof.root_hash, "112233");
        assert_eq!(proof.tree_size, "1000");
        assert_eq!(proof.hashes, vec!["aabbcc", "ddeeff"]);
    }

    #[test]
    fn test_tlog_entry_empty_inclusion_proof() {
        let mut rekor = create_test_rekor_entry();
        rekor.inclusion_proof = vec![];
        let tlog = build_tlog_entry(&rekor);
        assert!(tlog.inclusion_proof.is_none());
    }

    #[test]
    fn test_tlog_entry_empty_set() {
        let mut rekor = create_test_rekor_entry();
        rekor.signed_entry_timestamp = String::new();
        let tlog = build_tlog_entry(&rekor);
        assert!(tlog.inclusion_promise.is_none());
        assert!(tlog.signed_entry_timestamp().is_none());
    }

    /// A `log_id` that is not valid hex is not a Rekor log id we can transcode
    /// to the spec's base64 `bytes` form, so it is passed through unchanged
    /// rather than emitting silently-mangled base64.
    #[test]
    fn test_tlog_entry_non_hex_log_id_passes_through() {
        let mut rekor = create_test_rekor_entry();
        rekor.log_id = "not-hex-at-all!!".to_string();
        let tlog = build_tlog_entry(&rekor);
        assert_eq!(
            tlog.log_id.key_id, "not-hex-at-all!!",
            "a non-hex log id must pass through verbatim, not be re-encoded"
        );
    }

    /// Bundles wsc emitted at <= 0.11.0 carry the SET at the non-conformant
    /// top-level `signedEntryTimestamp`. Those must still be readable.
    #[test]
    fn test_legacy_top_level_set_is_still_accepted_on_read() {
        let json = br#"{
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "x509CertificateChain": { "certificates": [] },
                "tlogEntries": [{
                    "logIndex": "42",
                    "logId": { "keyId": "wNI9atQGlz8=" },
                    "integratedTime": "1704067200",
                    "signedEntryTimestamp": "bGVnYWN5U0VU"
                }]
            },
            "messageSignature": {
                "messageDigest": { "algorithm": "SHA2_256", "digest": "00" },
                "signature": "AA=="
            }
        }"#;
        let bundle = SigstoreBundle::from_json(json).expect("legacy shape must deserialize");
        let tlog = &bundle.verification_material.tlog_entries[0];
        assert_eq!(
            tlog.signed_entry_timestamp(),
            Some("bGVnYWN5U0VU"),
            "the legacy top-level SET must still be readable"
        );
        assert!(tlog.inclusion_promise.is_none());
    }

    #[test]
    fn test_tlog_entry_empty_body() {
        let mut rekor = create_test_rekor_entry();
        rekor.body = String::new();
        let tlog = build_tlog_entry(&rekor);
        assert!(tlog.canonicalized_body.is_none());
    }

    #[test]
    fn test_bundle_json_serialization_roundtrip() {
        let sig = create_test_keyless_signature();
        let bundle = SigstoreBundle::from_keyless_signature(&sig);

        let json = bundle.to_json().expect("Serialization failed");
        let parsed = SigstoreBundle::from_json(&json).expect("Deserialization failed");

        assert_eq!(parsed.media_type, bundle.media_type);
        assert_eq!(
            parsed.verification_material.x509_certificate_chain.certificates.len(),
            bundle.verification_material.x509_certificate_chain.certificates.len()
        );
        assert_eq!(
            parsed.verification_material.tlog_entries.len(),
            bundle.verification_material.tlog_entries.len()
        );
        assert_eq!(
            parsed.message_signature.signature,
            bundle.message_signature.signature
        );
        assert_eq!(
            parsed.message_signature.message_digest.algorithm,
            bundle.message_signature.message_digest.algorithm
        );
        assert_eq!(
            parsed.message_signature.message_digest.digest,
            bundle.message_signature.message_digest.digest
        );
    }

    #[test]
    fn test_bundle_json_structure() {
        let sig = create_test_keyless_signature();
        let bundle = SigstoreBundle::from_keyless_signature(&sig);

        let json_bytes = bundle.to_json().unwrap();
        let json_str = String::from_utf8(json_bytes).unwrap();

        // Verify expected JSON fields exist (camelCase)
        assert!(json_str.contains("mediaType"));
        assert!(json_str.contains("verificationMaterial"));
        assert!(json_str.contains("messageSignature"));
        assert!(json_str.contains("x509CertificateChain"));
        assert!(json_str.contains("tlogEntries"));
        assert!(json_str.contains("messageDigest"));
        assert!(json_str.contains("SHA2_256"));
    }

    #[test]
    fn test_pem_to_der_valid() {
        // Create a simple base64-encoded payload with PEM wrapping
        let payload = b"test certificate data";
        let b64 = BASE64.encode(payload);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            b64
        );

        let der = pem_to_der(&pem);
        assert_eq!(der, payload);
    }

    #[test]
    fn test_pem_to_der_multiline() {
        let payload = vec![0u8; 100]; // 100 bytes -> multi-line base64
        let b64 = BASE64.encode(&payload);

        // Split into 64-char lines like real PEM
        let lines: Vec<String> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect();
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            lines.join("\n")
        );

        let der = pem_to_der(&pem);
        assert_eq!(der, payload);
    }

    #[test]
    fn test_pem_to_der_invalid_base64_fallback() {
        let pem = "-----BEGIN CERTIFICATE-----\n!!!invalid!!!\n-----END CERTIFICATE-----";
        let der = pem_to_der(pem);
        // Should fall back to raw PEM bytes
        assert_eq!(der, pem.as_bytes());
    }

    #[test]
    fn test_bundle_empty_cert_chain() {
        let sig = KeylessSignature::new(
            vec![1, 2, 3],
            vec![],
            create_test_rekor_entry(),
            vec![0xaa, 0xbb],
        );

        let bundle = SigstoreBundle::from_keyless_signature(&sig);
        assert!(
            bundle
                .verification_material
                .x509_certificate_chain
                .certificates
                .is_empty()
        );

        // Should still roundtrip
        let json = bundle.to_json().unwrap();
        let parsed = SigstoreBundle::from_json(&json).unwrap();
        assert!(
            parsed
                .verification_material
                .x509_certificate_chain
                .certificates
                .is_empty()
        );
    }

    #[test]
    fn test_parse_inclusion_proof_valid() {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "hashes": ["aa", "bb", "cc"],
            "logIndex": 100,
            "rootHash": "deadbeef",
            "treeSize": 5000
        }))
        .unwrap();

        let proof = parse_inclusion_proof(&bytes).unwrap();
        assert_eq!(proof.log_index, "100");
        assert_eq!(proof.root_hash, "deadbeef");
        assert_eq!(proof.tree_size, "5000");
        assert_eq!(proof.hashes, vec!["aa", "bb", "cc"]);
    }

    #[test]
    fn test_parse_inclusion_proof_invalid() {
        let result = parse_inclusion_proof(b"not json");
        assert!(result.is_none());
    }

    #[test]
    fn test_certificate_serialization() {
        let cert = Certificate {
            raw_bytes: "AQIDBA==".to_string(),
        };

        let json = serde_json::to_string(&cert).unwrap();
        assert!(json.contains("rawBytes"));
        assert!(json.contains("AQIDBA=="));

        let parsed: Certificate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.raw_bytes, cert.raw_bytes);
    }

    #[test]
    fn test_message_digest_serialization() {
        let digest = MessageDigest {
            algorithm: "SHA2_256".to_string(),
            digest: "deadbeef".to_string(),
        };

        let json = serde_json::to_string(&digest).unwrap();
        assert!(json.contains("SHA2_256"));
        assert!(json.contains("deadbeef"));
    }
}
