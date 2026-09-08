use crate::Module;
use crate::error::WSError;
use crate::wasm_module::varint;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::Deserialize;
use serde_json;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Write};
use x509_parser::prelude::*;

// Re-export RekorEntry from the rekor module
use super::cert_verifier::CertificatePool;
pub use super::rekor::RekorEntry;
use super::rekor_verifier::RekorKeyring;

/// Deserialization view of the Rekor `hashedrekord/0.0.1` entry body.
///
/// Only the fields needed to bind the entry to a candidate
/// [`KeylessSignature`] bundle are modeled — extra fields in the body are
/// permitted and ignored. The signer side at `rekor.rs::upload_entry`
/// produces this exact shape.
#[derive(Debug, Deserialize)]
struct HashedrekordBody {
    kind: String,
    #[serde(rename = "apiVersion")]
    api_version: String,
    spec: HashedrekordSpec,
}

#[derive(Debug, Deserialize)]
struct HashedrekordSpec {
    signature: HashedrekordSignature,
    data: HashedrekordData,
}

#[derive(Debug, Deserialize)]
struct HashedrekordSignature {
    content: String,
    #[serde(rename = "publicKey")]
    public_key: HashedrekordPublicKey,
}

#[derive(Debug, Deserialize)]
struct HashedrekordPublicKey {
    content: String,
}

#[derive(Debug, Deserialize)]
struct HashedrekordData {
    hash: HashedrekordHash,
}

#[derive(Debug, Deserialize)]
struct HashedrekordHash {
    algorithm: String,
    value: String,
}

/// Binary format version for keyless signatures
pub const KEYLESS_VERSION: u8 = 0x02;

/// Signature type identifier for keyless signatures
pub const KEYLESS_SIG_TYPE: u8 = 0x02;

/// Standard signature type identifier
pub const STANDARD_SIG_TYPE: u8 = 0x01;

/// Maximum accepted depth of an embedded X.509 certificate chain.
///
/// Real-world Fulcio chains are length 2–3 (leaf + intermediate(s) + root).
/// Industry CAs ship at most 4–5. We cap at 8 — generous headroom while
/// rejecting adversarial 1000-cert chains that would trigger heap exhaustion
/// in `x509_parser` / WebPKI before any signature work begins.
pub const MAX_CHAIN_DEPTH: usize = 8;

/// Keyless signature custom section format
///
/// Binary format (extends existing wasmsig format):
/// ```text
/// [version: u8 = 0x02]              // New version for keyless
/// [sig_type: u8 = 0x02]             // 0x01 = standard, 0x02 = keyless
/// [signature_len: varint]
/// [signature: bytes]
/// [cert_chain_count: u8]
/// [cert_1_len: varint]
/// [cert_1: bytes]
/// ...
/// [rekor_entry_len: varint]
/// [rekor_entry: JSON bytes]
/// [module_hash_len: varint]
/// [module_hash: bytes]
/// ```
#[derive(Debug, Clone)]
pub struct KeylessSignature {
    /// ECDSA P-256 signature over `SHA256(module_bytes_without_signature_section)`,
    /// produced by the ephemeral key whose public half is in the leaf of
    /// [`cert_chain`](Self::cert_chain). Serialized in IEEE P1363 form (r || s).
    pub signature: Vec<u8>,
    /// X.509 certificate chain from Fulcio (PEM format)
    pub cert_chain: Vec<String>,
    /// Rekor transparency log entry
    pub rekor_entry: RekorEntry,
    /// SHA256 of the module **before** the keyless signature custom section
    /// was attached. Verifiers must recompute this from the candidate module
    /// (after stripping the signature section) and reject on mismatch.
    pub module_hash: Vec<u8>,
}

impl KeylessSignature {
    /// Create a new keyless signature
    pub fn new(
        signature: Vec<u8>,
        cert_chain: Vec<String>,
        rekor_entry: RekorEntry,
        module_hash: Vec<u8>,
    ) -> Self {
        Self {
            signature,
            cert_chain,
            rekor_entry,
            module_hash,
        }
    }

    /// Ingest an existing cosign / Sigstore bundle into a
    /// [`KeylessSignature`] the offline verifiers can consume (REQ-27,
    /// issue #260).
    ///
    /// Two on-disk shapes are recognised, in this order:
    ///
    /// * **Legacy `rekorBundle`** — the
    ///   `{ base64Signature, cert, rekorBundle: { SignedEntryTimestamp,
    ///   Payload } }` shape emitted by older cosign / `sigstore` clients.
    ///   This is varve v0.28.0's shape and the primary ingest target.
    /// * **Protobuf v0.3** —
    ///   `application/vnd.dev.sigstore.bundle.v0.3+json` with a
    ///   `verificationMaterial` / `messageSignature` envelope.
    ///
    /// # Faithful extraction
    ///
    /// Every value is copied straight out of the bundle; nothing is
    /// recomputed or normalised away. In particular `module_hash` is read
    /// from the Rekor body's `spec.data.hash.value` (legacy) or from
    /// `messageSignature.messageDigest.digest` (v0.3) — a corrupted digest
    /// in the input is propagated verbatim, never "fixed".
    ///
    /// # Errors
    ///
    /// Returns [`WSError::KeylessFormatError`] if the JSON is malformed, the
    /// shape is unrecognised, a required field is missing / mis-encoded, or a
    /// v0.3 bundle carries a raw public key instead of a Fulcio certificate.
    pub fn from_sigstore_bundle(json: &str) -> Result<Self, WSError> {
        let value: serde_json::Value = serde_json::from_str(json).map_err(|e| {
            WSError::KeylessFormatError(format!("Sigstore bundle is not valid JSON: {}", e))
        })?;
        let obj = value.as_object().ok_or_else(|| {
            WSError::KeylessFormatError("Sigstore bundle is not a JSON object".to_string())
        })?;

        // Shape detection, in order: legacy `rekorBundle`, then v0.3.
        if obj.contains_key("rekorBundle") {
            Self::from_legacy_rekor_bundle(&value)
        } else if obj
            .get("mediaType")
            .and_then(|m| m.as_str())
            .map(|s| s.starts_with("application/vnd.dev.sigstore.bundle"))
            .unwrap_or(false)
            || obj.contains_key("verificationMaterial")
        {
            Self::from_v03_bundle(&value)
        } else {
            Err(WSError::KeylessFormatError(
                "unrecognized Sigstore bundle format".to_string(),
            ))
        }
    }

    /// Map the legacy `rekorBundle` shape (varve's, the primary target).
    fn from_legacy_rekor_bundle(value: &serde_json::Value) -> Result<Self, WSError> {
        // signature: base64 -> raw bytes. NOTE: cosign emits ECDSA signatures
        // in ASN.1 DER form (`30 45 02 21 ...`), NOT the IEEE-P1363 (r||s)
        // form `KeylessSignature.signature` is documented to hold. We store
        // the DER bytes verbatim so the Rekor-body binding check (which
        // compares against the identical base64 in `body.spec.signature`)
        // succeeds; `verify_artifact_binding` currently expects P1363 and
        // would need a `Signature::from_der` path to accept an ingested
        // legacy bundle. See the REQ-27 report.
        let base64_sig = value["base64Signature"].as_str().ok_or_else(|| {
            WSError::KeylessFormatError("legacy Sigstore bundle missing 'base64Signature'".to_string())
        })?;
        let signature = BASE64.decode(base64_sig).map_err(|e| {
            WSError::KeylessFormatError(format!("'base64Signature' is not valid base64: {}", e))
        })?;

        // cert: base64 of PEM text -> PEM string(s). Fulcio may concatenate a
        // leaf plus intermediate(s); split into one chain entry per block.
        let cert_b64 = value["cert"].as_str().ok_or_else(|| {
            WSError::KeylessFormatError("legacy Sigstore bundle missing 'cert'".to_string())
        })?;
        let cert_pem_bytes = BASE64.decode(cert_b64).map_err(|e| {
            WSError::KeylessFormatError(format!("'cert' is not valid base64: {}", e))
        })?;
        let cert_pem = String::from_utf8(cert_pem_bytes).map_err(|e| {
            WSError::KeylessFormatError(format!("'cert' is not valid UTF-8 PEM: {}", e))
        })?;
        let cert_chain = split_pem_certificates(&cert_pem);

        let rekor_bundle = &value["rekorBundle"];
        let payload = &rekor_bundle["Payload"];

        // module_hash: read from the Rekor body's hashedrekord digest.
        let body_b64 = payload["body"].as_str().ok_or_else(|| {
            WSError::KeylessFormatError(
                "legacy Sigstore bundle missing 'rekorBundle.Payload.body'".to_string(),
            )
        })?;
        let module_hash = module_hash_from_hashedrekord_body(body_b64)?;

        let log_index = json_u64(&payload["logIndex"]).ok_or_else(|| {
            WSError::KeylessFormatError(
                "legacy Sigstore bundle 'rekorBundle.Payload.logIndex' is not an integer"
                    .to_string(),
            )
        })?;
        let log_id = payload["logID"].as_str().ok_or_else(|| {
            WSError::KeylessFormatError(
                "legacy Sigstore bundle missing 'rekorBundle.Payload.logID'".to_string(),
            )
        })?;
        let integrated_time = integrated_time_to_rfc3339(&payload["integratedTime"])?;
        let signed_entry_timestamp = rekor_bundle["SignedEntryTimestamp"].as_str().ok_or_else(|| {
            WSError::KeylessFormatError(
                "legacy Sigstore bundle missing 'rekorBundle.SignedEntryTimestamp'".to_string(),
            )
        })?;

        let rekor_entry = RekorEntry {
            // Legacy `rekorBundle` bundles carry no entry UUID. NOTE: an empty
            // uuid makes `rekor::is_rekor_skipped` return true, which the
            // ONLINE `KeylessVerifier::verify` path (signer.rs:601) treats as
            // "no transparency proof" and rejects. The offline SET material
            // (SignedEntryTimestamp + logID) and the body-binding inputs are
            // fully present here; accepting an ingested legacy bundle on the
            // online path needs a follow-up (synthesised/derived uuid). See
            // the REQ-27 report.
            uuid: String::new(),
            log_index,
            body: body_b64.to_string(),
            log_id: log_id.to_string(),
            // Legacy bundles carry only the SET, no Merkle inclusion proof.
            // Offline SET verification does not need it (inclusion_verified
            // stays false); left empty rather than fabricated.
            inclusion_proof: Vec::new(),
            signed_entry_timestamp: signed_entry_timestamp.to_string(),
            integrated_time,
        };

        Ok(Self::new(signature, cert_chain, rekor_entry, module_hash))
    }

    /// Map the protobuf-JSON v0.3 shape (cosign `--new-bundle-format`).
    fn from_v03_bundle(value: &serde_json::Value) -> Result<Self, WSError> {
        let vm = &value["verificationMaterial"];

        // The certificate requirement is checked FIRST — before decoding the
        // messageSignature envelope — so a raw-public-key (non-Fulcio) bundle
        // fails with the specific cert-requirement error, not an incidental
        // decode error further down. (Non-vacuity for the v0.3 fixture test.)
        let cert_chain: Vec<String> = if let Some(cert) = vm.get("certificate") {
            let raw = cert["rawBytes"].as_str().ok_or_else(|| {
                WSError::KeylessFormatError(
                    "Sigstore v0.3 'certificate' missing 'rawBytes'".to_string(),
                )
            })?;
            let der = BASE64.decode(raw).map_err(|e| {
                WSError::KeylessFormatError(format!(
                    "Sigstore v0.3 'certificate.rawBytes' is not valid base64: {}",
                    e
                ))
            })?;
            vec![der_to_pem(&der)]
        } else if let Some(chain) = vm.get("x509CertificateChain") {
            let certs = chain["certificates"].as_array().ok_or_else(|| {
                WSError::KeylessFormatError(
                    "Sigstore v0.3 'x509CertificateChain.certificates' is not an array".to_string(),
                )
            })?;
            let mut out = Vec::with_capacity(certs.len());
            for c in certs {
                let raw = c["rawBytes"].as_str().ok_or_else(|| {
                    WSError::KeylessFormatError(
                        "Sigstore v0.3 certificate missing 'rawBytes'".to_string(),
                    )
                })?;
                let der = BASE64.decode(raw).map_err(|e| {
                    WSError::KeylessFormatError(format!(
                        "Sigstore v0.3 certificate 'rawBytes' is not valid base64: {}",
                        e
                    ))
                })?;
                out.push(der_to_pem(&der));
            }
            out
        } else if vm.get("publicKey").is_some() {
            return Err(WSError::KeylessFormatError(
                "Sigstore v0.3 bundle carries a raw public key, not a Fulcio certificate; \
                 keyless offline verification requires a certificate (Fulcio/keyless) bundle"
                    .to_string(),
            ));
        } else {
            return Err(WSError::KeylessFormatError(
                "Sigstore v0.3 bundle has no certificate in verificationMaterial".to_string(),
            ));
        };

        // signature + module_hash from messageSignature.
        let msg_sig = &value["messageSignature"];
        let sig_b64 = msg_sig["signature"].as_str().ok_or_else(|| {
            WSError::KeylessFormatError(
                "Sigstore v0.3 bundle missing 'messageSignature.signature'".to_string(),
            )
        })?;
        let signature = BASE64.decode(sig_b64).map_err(|e| {
            WSError::KeylessFormatError(format!(
                "'messageSignature.signature' is not valid base64: {}",
                e
            ))
        })?;

        let digest = msg_sig["messageDigest"]["digest"].as_str().ok_or_else(|| {
            WSError::KeylessFormatError(
                "Sigstore v0.3 bundle missing 'messageSignature.messageDigest.digest'".to_string(),
            )
        })?;
        let module_hash = decode_v03_digest(digest)?;

        // Rekor entry from the first transparency-log entry.
        let tlog = vm["tlogEntries"]
            .as_array()
            .and_then(|a| a.first())
            .ok_or_else(|| {
                WSError::KeylessFormatError(
                    "Sigstore v0.3 bundle has no transparency-log entries".to_string(),
                )
            })?;

        let log_index = json_u64(&tlog["logIndex"]).ok_or_else(|| {
            WSError::KeylessFormatError("Sigstore v0.3 tlogEntry 'logIndex' is not an integer".to_string())
        })?;
        // logId.keyId is base64 of the log's key-id bytes; wsc's RekorEntry
        // stores the log id hex-encoded (matching the legacy `logID`).
        let log_id = match tlog["logId"]["keyId"].as_str() {
            Some(key_id_b64) => {
                let key_id = BASE64.decode(key_id_b64).map_err(|e| {
                    WSError::KeylessFormatError(format!(
                        "Sigstore v0.3 tlogEntry 'logId.keyId' is not valid base64: {}",
                        e
                    ))
                })?;
                hex::encode(key_id)
            }
            None => String::new(),
        };
        let integrated_time = integrated_time_to_rfc3339(&tlog["integratedTime"])?;
        let signed_entry_timestamp = tlog["inclusionPromise"]["signedEntryTimestamp"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let body = tlog["canonicalizedBody"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let rekor_entry = RekorEntry {
            uuid: String::new(),
            log_index,
            body,
            log_id,
            // The v0.3 `inclusionProof` (checkpoint + Merkle hashes) is not
            // reserialised: there is no keyless-v0.3 fixture to validate a
            // byte format against, and offline SET verification does not need
            // it. Left empty rather than fabricated (consistent with legacy).
            inclusion_proof: Vec::new(),
            signed_entry_timestamp,
            integrated_time,
        };

        Ok(Self::new(signature, cert_chain, rekor_entry, module_hash))
    }

    /// Serialize to bytes for WASM custom section
    ///
    /// # Binary Format
    ///
    /// The serialized format is:
    /// - Version byte (0x02)
    /// - Signature type byte (0x02 for keyless)
    /// - Signature length (varint) + signature bytes
    /// - Certificate chain count (u8)
    /// - For each certificate: length (varint) + PEM bytes
    /// - Rekor entry length (varint) + JSON bytes
    /// - Module hash length (varint) + hash bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, WSError> {
        let mut buffer = Vec::new();

        // Write version
        buffer
            .write_all(&[KEYLESS_VERSION])
            .map_err(|e| WSError::KeylessFormatError(format!("Failed to write version: {}", e)))?;

        // Write signature type
        buffer.write_all(&[KEYLESS_SIG_TYPE]).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write signature type: {}", e))
        })?;

        // Write signature
        varint::put_slice(&mut buffer, &self.signature).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write signature: {}", e))
        })?;

        // Write certificate chain count
        let cert_count = self.cert_chain.len();
        if cert_count > 255 {
            return Err(WSError::KeylessFormatError(format!(
                "Certificate chain too long: {} (max 255)",
                cert_count
            )));
        }
        buffer.write_all(&[cert_count as u8]).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write cert count: {}", e))
        })?;

        // Write each certificate
        for (i, cert_pem) in self.cert_chain.iter().enumerate() {
            varint::put_slice(&mut buffer, cert_pem.as_bytes()).map_err(|e| {
                WSError::KeylessFormatError(format!("Failed to write certificate {}: {}", i, e))
            })?;
        }

        // Serialize Rekor entry to JSON
        let rekor_json = serde_json::to_vec(&self.rekor_entry).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to serialize Rekor entry: {}", e))
        })?;

        // Write Rekor entry
        varint::put_slice(&mut buffer, &rekor_json).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write Rekor entry: {}", e))
        })?;

        // Write module hash
        varint::put_slice(&mut buffer, &self.module_hash).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to write module hash: {}", e))
        })?;

        Ok(buffer)
    }

    /// Deserialize from WASM custom section bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw bytes from the WASM custom section
    ///
    /// # Returns
    ///
    /// A parsed `KeylessSignature` or an error if the format is invalid
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WSError> {
        let mut reader = Cursor::new(bytes);

        // Read and verify version
        let mut version = [0u8; 1];
        std::io::Read::read_exact(&mut reader, &mut version)
            .map_err(|e| WSError::KeylessFormatError(format!("Failed to read version: {}", e)))?;
        if version[0] != KEYLESS_VERSION {
            return Err(WSError::KeylessFormatError(format!(
                "Unsupported version: {} (expected {})",
                version[0], KEYLESS_VERSION
            )));
        }

        // Read and verify signature type
        let mut sig_type = [0u8; 1];
        std::io::Read::read_exact(&mut reader, &mut sig_type).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to read signature type: {}", e))
        })?;
        if sig_type[0] != KEYLESS_SIG_TYPE {
            return Err(WSError::KeylessFormatError(format!(
                "Unsupported signature type: {} (expected {})",
                sig_type[0], KEYLESS_SIG_TYPE
            )));
        }

        // Read signature
        let signature = varint::get_slice(&mut reader)
            .map_err(|e| WSError::KeylessFormatError(format!("Failed to read signature: {}", e)))?;

        // Read certificate chain count
        let mut cert_count = [0u8; 1];
        std::io::Read::read_exact(&mut reader, &mut cert_count).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to read certificate count: {}", e))
        })?;

        // Read certificates
        let mut cert_chain = Vec::new();
        for i in 0..cert_count[0] {
            let cert_bytes = varint::get_slice(&mut reader).map_err(|e| {
                WSError::KeylessFormatError(format!("Failed to read certificate {}: {}", i, e))
            })?;
            let cert_pem = String::from_utf8(cert_bytes).map_err(|e| {
                WSError::KeylessFormatError(format!("Certificate {} is not valid UTF-8: {}", i, e))
            })?;
            cert_chain.push(cert_pem);
        }

        // Read Rekor entry
        let rekor_json = varint::get_slice(&mut reader).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to read Rekor entry: {}", e))
        })?;
        let rekor_entry: RekorEntry = serde_json::from_slice(&rekor_json).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to parse Rekor entry JSON: {}", e))
        })?;

        // Read module hash
        let module_hash = varint::get_slice(&mut reader).map_err(|e| {
            WSError::KeylessFormatError(format!("Failed to read module hash: {}", e))
        })?;

        Ok(Self {
            signature,
            cert_chain,
            rekor_entry,
            module_hash,
        })
    }

    /// Extract identity from the leaf certificate
    ///
    /// The identity is typically stored in the Subject Alternative Name (SAN) extension,
    /// which contains the email, URI, or other identity from the OIDC token.
    ///
    /// # Returns
    ///
    /// The identity string (e.g., "user@example.com", "https://github.com/user/repo")
    pub fn get_identity(&self) -> Result<String, WSError> {
        if self.cert_chain.is_empty() {
            return Err(WSError::CertificateError(
                "No certificates in chain".to_string(),
            ));
        }

        // Parse the leaf certificate (first in chain)
        let leaf_pem = &self.cert_chain[0];
        let (_, pem) = parse_x509_pem(leaf_pem.as_bytes())
            .map_err(|e| WSError::CertificateError(format!("Failed to parse PEM: {}", e)))?;

        let cert = pem.parse_x509().map_err(|e| {
            WSError::CertificateError(format!("Failed to parse X.509 certificate: {}", e))
        })?;

        // Look for Subject Alternative Name extension
        if let Some(san_ext) =
            cert.get_extension_unique(&oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)?
            && let ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() {
                // Try different SAN types in order of preference
                for name in &san.general_names {
                    match name {
                        GeneralName::RFC822Name(email) => {
                            return Ok(email.to_string());
                        }
                        GeneralName::URI(uri) => {
                            return Ok(uri.to_string());
                        }
                        GeneralName::DNSName(dns) => {
                            return Ok(dns.to_string());
                        }
                        _ => continue,
                    }
                }
            }

        // Fall back to subject common name if no SAN found
        for rdn in cert.subject().iter() {
            for attr in rdn.iter() {
                if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME
                    && let Ok(cn) = attr.as_str() {
                        return Ok(cn.to_string());
                    }
            }
        }

        Err(WSError::CertificateError(
            "No identity found in certificate".to_string(),
        ))
    }

    /// Extract issuer from the leaf certificate
    ///
    /// The issuer identifies the OIDC provider that issued the identity token
    /// (e.g., "https://accounts.google.com", "https://token.actions.githubusercontent.com").
    ///
    /// For Fulcio certificates, this is stored in a custom OID extension.
    ///
    /// # Returns
    ///
    /// The issuer URL string
    pub fn get_issuer(&self) -> Result<String, WSError> {
        if self.cert_chain.is_empty() {
            return Err(WSError::CertificateError(
                "No certificates in chain".to_string(),
            ));
        }

        // Parse the leaf certificate (first in chain)
        let leaf_pem = &self.cert_chain[0];
        let (_, pem) = parse_x509_pem(leaf_pem.as_bytes())
            .map_err(|e| WSError::CertificateError(format!("Failed to parse PEM: {}", e)))?;

        let cert = pem.parse_x509().map_err(|e| {
            WSError::CertificateError(format!("Failed to parse X.509 certificate: {}", e))
        })?;

        // Sigstore/Fulcio uses custom OIDs for OIDC issuer:
        // - 1.3.6.1.4.1.57264.1.1 (v1, deprecated but still common)
        // - 1.3.6.1.4.1.57264.1.8 (v2, Issuer V2)
        const OIDC_ISSUER_V1: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 1];
        const OIDC_ISSUER_V2: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 8];

        // Try to find the OIDC issuer in certificate extensions
        for ext in cert.extensions() {
            let oid_components: Vec<u64> = match ext.oid.iter() {
                Some(iter) => iter.collect(),
                None => continue,
            };

            // Check for OIDC Issuer v1 or v2
            if oid_components == OIDC_ISSUER_V1 || oid_components == OIDC_ISSUER_V2 {
                // The extension value is a UTF8String containing the issuer URL
                // It may be wrapped in ASN.1 encoding, try to extract the string
                let value = ext.value;

                // Try to parse as ASN.1 UTF8String first
                if let Ok((_, utf8_str)) = der_parser::der::parse_der_utf8string(value) {
                    if let Ok(s) = utf8_str.as_str() {
                        return Ok(s.to_string());
                    }
                }

                // Fallback: try to interpret raw bytes as UTF-8
                if let Ok(s) = std::str::from_utf8(value) {
                    return Ok(s.to_string());
                }
            }
        }

        // Fallback: extract certificate issuer common name
        // This is not the OIDC issuer, but provides some information
        for rdn in cert.issuer().iter() {
            for attr in rdn.iter() {
                if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME
                    && let Ok(cn) = attr.as_str()
                {
                    return Ok(cn.to_string());
                }
            }
        }

        Err(WSError::CertificateError(
            "No OIDC issuer found in certificate".to_string(),
        ))
    }

    /// Verify the certificate chain
    ///
    /// This performs full RFC 5280 certificate chain validation:
    /// - Validates certificate chain up to Fulcio root CA
    /// - Checks certificate signatures at each level
    /// - Verifies validity periods match Rekor integrated_time
    /// - Validates certificate extensions (Key Usage, Extended Key Usage)
    ///
    /// # Returns
    ///
    /// Ok if the certificate chain is valid, error otherwise
    ///
    /// # Security
    ///
    /// Uses WebPKI (rustls-webpki) for cryptographic verification.
    /// Trust anchors are embedded from Sigstore TUF repository.
    pub fn verify_cert_chain(&self) -> Result<(), WSError> {
        if self.cert_chain.is_empty() {
            return Err(WSError::CertificateError(
                "Empty certificate chain".to_string(),
            ));
        }

        // SECURITY: bound chain depth before invoking x509_parser/WebPKI.
        // An adversarial 1000-cert chain would otherwise trigger heap
        // exhaustion during PEM/DER decoding.
        if self.cert_chain.len() > MAX_CHAIN_DEPTH {
            return Err(WSError::ChainTooDeep(MAX_CHAIN_DEPTH));
        }

        // Load Fulcio trusted roots
        let cert_pool = CertificatePool::from_embedded_trust_root().map_err(|e| {
            WSError::CertificateError(format!("Failed to load trusted roots: {}", e))
        })?;

        // Parse integrated_time from Rekor entry (RFC3339 format)
        let integrated_time =
            chrono::DateTime::parse_from_rfc3339(&self.rekor_entry.integrated_time).map_err(
                |e| WSError::CertificateError(format!("Failed to parse integrated_time: {}", e)),
            )?;

        let integrated_time_unix = integrated_time.timestamp();

        // Verify the leaf certificate (first in chain)
        // The leaf certificate must chain up to a trusted Fulcio root CA
        let leaf_cert_pem = self
            .cert_chain
            .first()
            .ok_or_else(|| WSError::CertificateError("No leaf certificate in chain".to_string()))?;

        cert_pool
            .verify_pem_cert(leaf_cert_pem.as_bytes(), integrated_time_unix)
            .map_err(|e| {
                WSError::CertificateError(format!("Certificate verification failed: {}", e))
            })?;

        log::debug!("Certificate chain verified successfully");
        Ok(())
    }

    /// Verify the Rekor inclusion proof
    ///
    /// This performs complete Rekor transparency log verification:
    /// - Verifies the Merkle tree inclusion proof
    /// - Checks the signed entry timestamp (SET)
    /// - Validates against Rekor's public key
    /// - Verifies checkpoint signatures when available
    ///
    /// # Security
    ///
    /// This ensures that the signature was actually logged in Rekor's
    /// transparency log, providing non-repudiation and auditability.
    ///
    /// # Returns
    ///
    /// Ok if the inclusion proof is valid, error otherwise
    pub fn verify_rekor_inclusion(&self) -> Result<(), WSError> {
        log::debug!(
            "Verifying Rekor inclusion proof for entry {}",
            self.rekor_entry.uuid
        );

        // Load Rekor public keys from embedded trust root
        let keyring = RekorKeyring::from_embedded_trust_root()
            .map_err(|e| WSError::RekorError(format!("Failed to load Rekor public keys: {}", e)))?;

        // Verify the inclusion proof using the full verification implementation
        // This performs:
        // 1. Merkle tree inclusion proof verification (RFC 6962)
        // 2. Signed Entry Timestamp (SET) verification
        // 3. Checkpoint signature verification (if available)
        keyring.verify_inclusion_proof(&self.rekor_entry)?;

        log::debug!("Rekor inclusion proof verified successfully");
        Ok(())
    }

    /// Verify that this signature actually binds to the given module.
    ///
    /// This is the artifact-integrity step of keyless verification. It is
    /// **independent of** certificate chain validation and Rekor SET
    /// verification, which only attest to "this Fulcio cert exists and is
    /// known to the transparency log." Without this check, an attacker who
    /// obtains any valid Fulcio cert + Rekor entry can splice the signature
    /// blob onto an arbitrary module and the verifier will accept it
    /// (issue #135).
    ///
    /// Two checks run in sequence; failing either rejects the module:
    ///
    /// 1. **Hash binding.** Strip the embedded signature custom section,
    ///    serialize the remaining module, recompute its SHA-256, and require
    ///    it to equal [`Self::module_hash`]. This proves the candidate
    ///    module's bytes are the bytes the signer covered.
    /// 2. **Signature authenticity.** Extract the ECDSA P-256 public key
    ///    from the leaf certificate and verify [`Self::signature`] is a
    ///    valid signature over `SHA256(stripped_module_bytes)`. This proves
    ///    the cert's holder actually signed *this* hash, not someone else's.
    ///
    /// On any failure, returns [`WSError::VerificationFailed`] and emits a
    /// `log::error!` with the specific reason. The error variant does not
    /// distinguish hash vs. signature failure to avoid leaking which check
    /// a tampered artifact tripped.
    pub fn verify_artifact_binding(&self, module: &Module) -> Result<(), WSError> {
        use ecdsa::signature::DigestVerifier;
        use p256::ecdsa::{Signature as P256Signature, VerifyingKey};

        // Step 1: Recompute the module hash over the bytes the signer
        // covered (i.e., the module with the signature custom section
        // removed). The sign path computes the hash *before* attaching the
        // signature, so verify must mirror that by stripping it.
        let (unsigned_module, _stripped_signature_bytes) = module
            .clone()
            .detach_signature()
            .map_err(|_| WSError::NoSignatures)?;

        let mut unsigned_bytes = Vec::new();
        unsigned_module.serialize(&mut unsigned_bytes).map_err(|e| {
            WSError::InternalError(format!("Failed to serialize stripped module: {}", e))
        })?;

        let recomputed_hash = Sha256::digest(&unsigned_bytes);
        if &recomputed_hash[..] != self.module_hash.as_slice() {
            log::error!(
                "Keyless artifact binding rejected: module hash mismatch \
                 (expected {}, recomputed {})",
                hex::encode(&self.module_hash),
                hex::encode(recomputed_hash),
            );
            return Err(WSError::VerificationFailed);
        }

        // Step 2: Extract the leaf cert's SPKI as a P-256 verifying key and
        // verify the signature blob against the recomputed digest. The sign
        // path uses `signing_key.sign_digest(Sha256)` with the same module
        // bytes — verify must use `verify_digest` symmetrically.
        let leaf_pem = self.cert_chain.first().ok_or_else(|| {
            log::error!("Keyless artifact binding rejected: empty certificate chain");
            WSError::VerificationFailed
        })?;

        let (_, pem) = parse_x509_pem(leaf_pem.as_bytes()).map_err(|e| {
            log::error!(
                "Keyless artifact binding rejected: failed to parse leaf cert PEM: {}",
                e
            );
            WSError::VerificationFailed
        })?;
        let cert = pem.parse_x509().map_err(|e| {
            log::error!(
                "Keyless artifact binding rejected: failed to parse leaf X.509: {}",
                e
            );
            WSError::VerificationFailed
        })?;

        // Fulcio issues ECDSA P-256 keys (matching the sign path at
        // signer.rs `SigningKey::<p256::NistP256>::random`). The SPKI's
        // BIT STRING `data` field is the SEC1-encoded uncompressed point
        // (0x04 || x || y) for P-256, which `from_sec1_bytes` accepts.
        let spki_bits = cert.public_key().subject_public_key.data.as_ref();
        let verifying_key = VerifyingKey::from_sec1_bytes(spki_bits).map_err(|e| {
            log::error!(
                "Keyless artifact binding rejected: leaf cert SPKI is not a valid \
                 ECDSA P-256 key: {}",
                e
            );
            WSError::VerificationFailed
        })?;

        let signature = P256Signature::from_slice(&self.signature).map_err(|e| {
            log::error!(
                "Keyless artifact binding rejected: signature blob is not a valid \
                 ECDSA P-256 signature: {}",
                e
            );
            WSError::VerificationFailed
        })?;

        let mut hasher = Sha256::new();
        hasher.update(&unsigned_bytes);
        verifying_key.verify_digest(hasher, &signature).map_err(|e| {
            log::error!(
                "Keyless artifact binding rejected: ECDSA verify failed: {}",
                e
            );
            WSError::VerificationFailed
        })?;

        log::debug!("Keyless artifact binding verified successfully");
        Ok(())
    }

    /// Verify that the Rekor entry's body binds to *this* bundle.
    ///
    /// [`verify_artifact_binding`](Self::verify_artifact_binding) proves
    /// the signature, leaf cert and module are mutually consistent.
    /// [`verify_rekor_inclusion`](Self::verify_rekor_inclusion) (and the
    /// SET check used by [`KeylessVerifier`](super::signer::KeylessVerifier))
    /// prove the Rekor entry was logged by Rekor. Neither proves the
    /// Rekor entry actually references *this* bundle — without that
    /// binding, an attacker with any valid Fulcio cert can sign a
    /// malicious module and stuff in **any unrelated** Rekor entry, and
    /// `verify --keyless` returns exit 0 (issue #135 UCA-2).
    ///
    /// This check decodes the entry body — a base64'd `hashedrekord/0.0.1`
    /// JSON document — and asserts three equalities against the bundle:
    ///
    /// 1. `body.spec.data.hash.algorithm == "sha256"` and
    ///    `body.spec.data.hash.value == hex(self.module_hash)`.
    /// 2. `base64_decode(body.spec.signature.content) == self.signature`.
    /// 3. The leaf certificate parsed from
    ///    `base64_decode(body.spec.signature.publicKey.content)` matches
    ///    `self.cert_chain[0]` byte-for-byte at the DER level.
    ///
    /// All failures return [`WSError::VerificationFailed`] with a
    /// `log::error!` describing the specific mismatch; the error variant
    /// itself does not discriminate, to avoid giving an attacker an
    /// oracle for which leg of the check rejected their forgery.
    pub fn verify_rekor_body_binds_to_bundle(&self) -> Result<(), WSError> {
        // 1. Decode the body and shape-check kind/version. Rekor's API
        // returns the body as base64-encoded JSON; the signer side at
        // `rekor.rs::upload_entry` builds it as `hashedrekord/0.0.1`.
        let body_bytes = BASE64.decode(&self.rekor_entry.body).map_err(|e| {
            log::error!(
                "Rekor body binding rejected: body is not valid base64: {}",
                e
            );
            WSError::VerificationFailed
        })?;

        let body: HashedrekordBody = serde_json::from_slice(&body_bytes).map_err(|e| {
            log::error!(
                "Rekor body binding rejected: body is not a hashedrekord JSON: {}",
                e
            );
            WSError::VerificationFailed
        })?;

        if body.kind != "hashedrekord" {
            log::error!(
                "Rekor body binding rejected: unexpected kind '{}', want 'hashedrekord'",
                body.kind
            );
            return Err(WSError::VerificationFailed);
        }
        if body.api_version != "0.0.1" {
            log::error!(
                "Rekor body binding rejected: unsupported hashedrekord apiVersion '{}', \
                 want '0.0.1'",
                body.api_version
            );
            return Err(WSError::VerificationFailed);
        }

        // 2. Artifact hash equality: body says what was logged, bundle
        // carries what was signed. Without this, an attacker can pair
        // their signature over module M' with someone else's Rekor
        // entry that logged a different hash for module M.
        if body.spec.data.hash.algorithm.to_ascii_lowercase() != "sha256" {
            log::error!(
                "Rekor body binding rejected: unsupported hash algorithm '{}', want 'sha256'",
                body.spec.data.hash.algorithm
            );
            return Err(WSError::VerificationFailed);
        }
        let bundle_hash_hex = hex::encode(&self.module_hash);
        if !body
            .spec
            .data
            .hash
            .value
            .eq_ignore_ascii_case(&bundle_hash_hex)
        {
            log::error!(
                "Rekor body binding rejected: body artifact hash '{}' does not match bundle \
                 module_hash '{}'",
                body.spec.data.hash.value,
                bundle_hash_hex,
            );
            return Err(WSError::VerificationFailed);
        }

        // 3. Signature blob equality: body says which signature was
        // logged, bundle carries which signature is being presented.
        // Without this, an attacker can splice a body whose hash happens
        // to match but whose recorded signature came from a different
        // signing event.
        let body_sig = BASE64.decode(&body.spec.signature.content).map_err(|e| {
            log::error!(
                "Rekor body binding rejected: body signature is not valid base64: {}",
                e
            );
            WSError::VerificationFailed
        })?;
        if body_sig.as_slice() != self.signature.as_slice() {
            log::error!(
                "Rekor body binding rejected: body signature bytes do not match bundle \
                 signature (body_len={}, bundle_len={})",
                body_sig.len(),
                self.signature.len(),
            );
            return Err(WSError::VerificationFailed);
        }

        // 4. Public-key binding: the body's publicKey.content is a
        // base64'd PEM that the signer uploaded as
        // `cert_chain.join("\n")`. Different Rekor clients could
        // serialize cert chain joining differently, so the robust check
        // is to extract the leaf CERTIFICATE block from the decoded
        // bytes, parse it to DER, and compare to the bundle's leaf cert
        // (also normalised via PEM→DER). Direct byte equality on the
        // raw PEM would over-reject on benign whitespace / line-ending
        // differences.
        let body_pubkey_bytes = BASE64
            .decode(&body.spec.signature.public_key.content)
            .map_err(|e| {
                log::error!(
                    "Rekor body binding rejected: body publicKey is not valid base64: {}",
                    e
                );
                WSError::VerificationFailed
            })?;
        let body_leaf_der = first_certificate_der(&body_pubkey_bytes).ok_or_else(|| {
            log::error!(
                "Rekor body binding rejected: body publicKey contains no CERTIFICATE PEM block"
            );
            WSError::VerificationFailed
        })?;

        let bundle_leaf_pem = self.cert_chain.first().ok_or_else(|| {
            log::error!("Rekor body binding rejected: bundle has no leaf certificate");
            WSError::VerificationFailed
        })?;
        let bundle_leaf_der =
            first_certificate_der(bundle_leaf_pem.as_bytes()).ok_or_else(|| {
                log::error!(
                    "Rekor body binding rejected: bundle leaf cert is not a parseable PEM \
                     CERTIFICATE block"
                );
                WSError::VerificationFailed
            })?;

        if body_leaf_der != bundle_leaf_der {
            log::error!(
                "Rekor body binding rejected: body leaf cert DER differs from bundle leaf \
                 cert DER (body_len={}, bundle_len={})",
                body_leaf_der.len(),
                bundle_leaf_der.len(),
            );
            return Err(WSError::VerificationFailed);
        }

        log::debug!("Rekor body binding verified successfully");
        Ok(())
    }
}

/// Parse a PEM-encoded byte slice and return the DER bytes of the first
/// CERTIFICATE block. Returns `None` if no CERTIFICATE block is present
/// or the PEM is malformed. Used to normalise leaf-cert comparison
/// across serializations that may differ on whitespace or trailing
/// concatenated certs.
fn first_certificate_der(pem_bytes: &[u8]) -> Option<Vec<u8>> {
    // Use the absolute path `::pem` because `x509_parser::prelude::*`
    // brings in a `pem` module that would otherwise shadow the crate.
    for entry in ::pem::parse_many(pem_bytes).ok()?.into_iter() {
        if entry.tag() == "CERTIFICATE" {
            return Some(entry.contents().to_vec());
        }
    }
    None
}

/// Split a PEM string that may contain several concatenated CERTIFICATE
/// blocks into one string per certificate. If no END marker is present the
/// whole (trimmed) input is returned as a single entry.
fn split_pem_certificates(pem: &str) -> Vec<String> {
    const END: &str = "-----END CERTIFICATE-----";
    let mut certs = Vec::new();
    let mut rest = pem;
    while let Some(idx) = rest.find(END) {
        let end = idx + END.len();
        let block = rest[..end].trim_start().to_string();
        certs.push(block);
        rest = &rest[end..];
    }
    if certs.is_empty() {
        certs.push(pem.trim().to_string());
    }
    certs
}

/// Wrap DER certificate bytes in a PEM CERTIFICATE block (64-column base64).
fn der_to_pem(der: &[u8]) -> String {
    let b64 = BASE64.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        // chunk is ASCII base64 and therefore always valid UTF-8.
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// Decode a base64 `hashedrekord` body and read `spec.data.hash.value` as the
/// hex artifact digest, returning the 32-byte SHA-256. The digest is read
/// straight from the body — never recomputed — so a corrupted input digest is
/// propagated faithfully.
fn module_hash_from_hashedrekord_body(body_b64: &str) -> Result<Vec<u8>, WSError> {
    let body_bytes = BASE64.decode(body_b64).map_err(|e| {
        WSError::KeylessFormatError(format!("Rekor body is not valid base64: {}", e))
    })?;
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
        WSError::KeylessFormatError(format!("Rekor body is not valid JSON: {}", e))
    })?;
    let hash_hex = body["spec"]["data"]["hash"]["value"]
        .as_str()
        .ok_or_else(|| {
            WSError::KeylessFormatError("Rekor body missing 'spec.data.hash.value'".to_string())
        })?;
    let module_hash = hex::decode(hash_hex).map_err(|e| {
        WSError::KeylessFormatError(format!("Rekor body hash value is not valid hex: {}", e))
    })?;
    if module_hash.len() != 32 {
        return Err(WSError::KeylessFormatError(format!(
            "Rekor body hash is {} bytes, expected 32 (SHA-256)",
            module_hash.len()
        )));
    }
    Ok(module_hash)
}

/// Decode a v0.3 `messageDigest.digest`. Real cosign v0.3 bundles encode the
/// digest as base64; wsc's own [`SigstoreBundle::from_keyless_signature`]
/// currently emits it as hex, so both encodings are accepted here.
fn decode_v03_digest(digest: &str) -> Result<Vec<u8>, WSError> {
    let bytes = if digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        // wsc-emitted hex form.
        hex::decode(digest).map_err(|e| {
            WSError::KeylessFormatError(format!("messageDigest.digest hex decode failed: {}", e))
        })?
    } else {
        // cosign wire form (base64).
        BASE64.decode(digest).map_err(|e| {
            WSError::KeylessFormatError(format!(
                "messageDigest.digest is neither 64-char hex nor base64: {}",
                e
            ))
        })?
    };
    if bytes.len() != 32 {
        return Err(WSError::KeylessFormatError(format!(
            "messageDigest.digest is {} bytes, expected 32 (SHA-256)",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Read a JSON value holding an unsigned integer encoded either as a number
/// (legacy `logIndex`) or a decimal string (v0.3 `logIndex`).
fn json_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
}

/// Read a JSON value holding a signed integer as a number or decimal string.
fn json_i64(v: &serde_json::Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
}

/// Convert an `integratedTime` (Unix seconds, given as a JSON number or
/// string) into the RFC3339 form the wsc `RekorEntry.integrated_time` field
/// is documented to hold. [`KeylessSignature::verify_cert_chain`] parses this
/// field with `parse_from_rfc3339`, so storing bare Unix seconds would make
/// every ingested bundle fail cert-chain verification.
fn integrated_time_to_rfc3339(v: &serde_json::Value) -> Result<String, WSError> {
    let secs = json_i64(v).ok_or_else(|| {
        WSError::KeylessFormatError("integratedTime is not an integer".to_string())
    })?;
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0).ok_or_else(|| {
        WSError::KeylessFormatError(format!("integratedTime {} is out of range", secs))
    })?;
    Ok(dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `der_to_pem` (used by the v0.3 cert path, which neither committed
    /// fixture exercises) must emit a PEM block that round-trips back to the
    /// exact DER via `first_certificate_der`. Guards against a malformed-PEM
    /// silent drop of the leaf cert on future keyless v0.3 bundles.
    #[test]
    fn test_der_to_pem_round_trips_through_first_certificate_der() {
        // >64 bytes so the base64 body spans multiple 64-column lines.
        let der: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let pem = der_to_pem(&der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
        assert_eq!(
            first_certificate_der(pem.as_bytes()).as_deref(),
            Some(&der[..]),
            "der_to_pem output must parse back to the original DER"
        );
    }

    // ---------------------------------------------------------------
    // `from_sigstore_bundle` error paths.
    //
    // Every test below drives ONE branch with the smallest input that
    // reaches it and asserts the SPECIFIC message that branch emits, so
    // deleting the branch (or letting control fall through to a
    // neighbouring error) fails the test rather than silently passing.
    // ---------------------------------------------------------------

    /// Run `from_sigstore_bundle` on `json`, require a `KeylessFormatError`,
    /// and return its message for substring assertions.
    fn format_err(json: &str) -> String {
        match KeylessSignature::from_sigstore_bundle(json) {
            Err(WSError::KeylessFormatError(msg)) => msg,
            Err(other) => panic!("expected KeylessFormatError, got: {other:?}"),
            Ok(_) => panic!("expected an error, but the bundle ingested"),
        }
    }

    /// Base64 of a minimal, well-formed `hashedrekord` body whose
    /// `spec.data.hash.value` is a valid 32-byte SHA-256 in hex.
    fn valid_body_b64() -> String {
        BASE64.encode(
            serde_json::json!({
                "apiVersion": "0.0.1",
                "kind": "hashedrekord",
                "spec": { "data": { "hash": { "algorithm": "sha256", "value": "aa".repeat(32) } } }
            })
            .to_string(),
        )
    }

    /// A minimal legacy `rekorBundle` bundle that ingests successfully.
    /// Each error test clones this and breaks exactly one field, so the
    /// branch under test is the only thing that can fail.
    fn valid_legacy() -> serde_json::Value {
        serde_json::json!({
            "base64Signature": BASE64.encode([1u8, 2, 3]),
            "cert": BASE64.encode("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----"),
            "rekorBundle": {
                "SignedEntryTimestamp": BASE64.encode([9u8, 9, 9]),
                "Payload": {
                    "body": valid_body_b64(),
                    "integratedTime": 1_700_000_000i64,
                    "logIndex": 42i64,
                    "logID": "c0d23d6a",
                }
            }
        })
    }

    /// The base fixture must actually ingest — otherwise every "break one
    /// field" test below could be passing for the wrong reason.
    #[test]
    fn legacy_base_is_valid_control() {
        let sig = KeylessSignature::from_sigstore_bundle(&valid_legacy().to_string())
            .expect("the base legacy bundle used by the error tests must ingest");
        assert_eq!(sig.module_hash, hex::decode("aa".repeat(32)).unwrap());
        assert_eq!(sig.rekor_entry.log_index, 42);
        assert_eq!(sig.rekor_entry.log_id, "c0d23d6a");
        assert_eq!(sig.rekor_entry.integrated_time, "2023-11-14T22:13:20Z");
    }

    // --- dispatch ---------------------------------------------------

    #[test]
    fn from_sigstore_bundle_rejects_malformed_json() {
        assert!(format_err("{not json").contains("Sigstore bundle is not valid JSON"));
    }

    #[test]
    fn from_sigstore_bundle_rejects_non_object_json() {
        // Valid JSON, but an array — must hit the "not a JSON object" branch,
        // not the JSON-parse branch above nor the unrecognised-format branch.
        assert!(format_err("[1, 2, 3]").contains("Sigstore bundle is not a JSON object"));
        assert!(format_err("\"a string\"").contains("Sigstore bundle is not a JSON object"));
    }

    #[test]
    fn from_sigstore_bundle_dispatches_v03_on_media_type_alone() {
        // A `mediaType` starting with the sigstore bundle prefix routes to the
        // v0.3 parser even with no `verificationMaterial` key — proving the
        // mediaType arm of the dispatch, not the verificationMaterial arm.
        let msg = format_err(
            &serde_json::json!({ "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json" })
                .to_string(),
        );
        assert!(
            msg.contains("no certificate in verificationMaterial"),
            "got: {msg}"
        );
    }

    // --- legacy error paths -----------------------------------------

    #[test]
    fn legacy_missing_base64_signature() {
        let mut b = valid_legacy();
        b.as_object_mut().unwrap().remove("base64Signature");
        assert!(format_err(&b.to_string()).contains("missing 'base64Signature'"));
    }

    #[test]
    fn legacy_base64_signature_not_base64() {
        let mut b = valid_legacy();
        b["base64Signature"] = serde_json::json!("!!!not base64!!!");
        assert!(
            format_err(&b.to_string()).contains("'base64Signature' is not valid base64"),
            "expected the base64 decode error for the signature"
        );
    }

    #[test]
    fn legacy_missing_cert() {
        let mut b = valid_legacy();
        b.as_object_mut().unwrap().remove("cert");
        assert!(format_err(&b.to_string()).contains("legacy Sigstore bundle missing 'cert'"));
    }

    #[test]
    fn legacy_cert_not_base64() {
        let mut b = valid_legacy();
        b["cert"] = serde_json::json!("!!!not base64!!!");
        assert!(format_err(&b.to_string()).contains("'cert' is not valid base64"));
    }

    #[test]
    fn legacy_cert_not_utf8() {
        let mut b = valid_legacy();
        // Valid base64 that decodes to bytes which are not valid UTF-8, so the
        // decode succeeds and the FROM_UTF8 branch is the one that fires.
        b["cert"] = serde_json::json!(BASE64.encode([0xffu8, 0xfe, 0xfd]));
        let msg = format_err(&b.to_string());
        assert!(
            msg.contains("'cert' is not valid UTF-8 PEM"),
            "expected the UTF-8 branch, got: {msg}"
        );
    }

    #[test]
    fn legacy_missing_body() {
        let mut b = valid_legacy();
        b["rekorBundle"]["Payload"]
            .as_object_mut()
            .unwrap()
            .remove("body");
        assert!(
            format_err(&b.to_string()).contains("missing 'rekorBundle.Payload.body'"),
            "expected the missing-body branch"
        );
    }

    #[test]
    fn legacy_log_index_missing_or_not_a_number() {
        // Absent.
        let mut b = valid_legacy();
        b["rekorBundle"]["Payload"]
            .as_object_mut()
            .unwrap()
            .remove("logIndex");
        assert!(
            format_err(&b.to_string()).contains("'rekorBundle.Payload.logIndex' is not an integer")
        );

        // Present but neither a number nor a decimal string.
        let mut b = valid_legacy();
        b["rekorBundle"]["Payload"]["logIndex"] = serde_json::json!("not-a-number");
        assert!(
            format_err(&b.to_string()).contains("'rekorBundle.Payload.logIndex' is not an integer")
        );
    }

    #[test]
    fn legacy_log_index_accepts_decimal_string() {
        // Non-vacuity partner of the test above: `json_u64` must still accept
        // the string form, otherwise the "not an integer" assertion could be
        // passing because the parser rejects every string.
        let mut b = valid_legacy();
        b["rekorBundle"]["Payload"]["logIndex"] = serde_json::json!("2544945534");
        let sig = KeylessSignature::from_sigstore_bundle(&b.to_string()).expect("string logIndex");
        assert_eq!(sig.rekor_entry.log_index, 2544945534);
    }

    #[test]
    fn legacy_missing_log_id() {
        let mut b = valid_legacy();
        b["rekorBundle"]["Payload"]
            .as_object_mut()
            .unwrap()
            .remove("logID");
        assert!(format_err(&b.to_string()).contains("missing 'rekorBundle.Payload.logID'"));
    }

    #[test]
    fn legacy_integrated_time_not_a_number() {
        let mut b = valid_legacy();
        b["rekorBundle"]["Payload"]["integratedTime"] = serde_json::json!({ "not": "a number" });
        assert!(format_err(&b.to_string()).contains("integratedTime is not an integer"));
    }

    #[test]
    fn legacy_missing_signed_entry_timestamp() {
        let mut b = valid_legacy();
        b["rekorBundle"]
            .as_object_mut()
            .unwrap()
            .remove("SignedEntryTimestamp");
        assert!(
            format_err(&b.to_string()).contains("missing 'rekorBundle.SignedEntryTimestamp'"),
            "the SET is the only offline transparency proof a legacy bundle \
             carries; its absence must be an error, never a silent empty"
        );
    }

    // --- v0.3 error paths -------------------------------------------

    /// A minimal v0.3 bundle that ingests successfully. Structural only: the
    /// v0.3 parser performs no cryptographic checks, so synthetic bytes are
    /// sufficient for these branch tests (the real-material happy paths live
    /// in `tests/sigstore_bundle.rs`).
    fn valid_v03() -> serde_json::Value {
        serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "certificate": { "rawBytes": BASE64.encode([1u8, 2, 3]) },
                "tlogEntries": [{
                    "logIndex": "42",
                    "logId": { "keyId": BASE64.encode([0xc0u8, 0xd2]) },
                    "integratedTime": "1700000000",
                }],
            },
            "messageSignature": {
                "messageDigest": { "algorithm": "SHA2_256", "digest": BASE64.encode([7u8; 32]) },
                "signature": BASE64.encode([4u8, 5, 6]),
            },
        })
    }

    #[test]
    fn v03_base_is_valid_control() {
        let sig = KeylessSignature::from_sigstore_bundle(&valid_v03().to_string())
            .expect("the base v0.3 bundle used by the error tests must ingest");
        assert_eq!(sig.signature, vec![4, 5, 6]);
        assert_eq!(sig.module_hash, vec![7u8; 32]);
        assert_eq!(sig.rekor_entry.log_index, 42);
        // base64 keyId is re-encoded as hex.
        assert_eq!(sig.rekor_entry.log_id, "c0d2");
        assert_eq!(sig.cert_chain.len(), 1);
        assert_eq!(
            first_certificate_der(sig.cert_chain[0].as_bytes()),
            Some(vec![1, 2, 3]),
            "the singular `certificate.rawBytes` DER must survive der_to_pem"
        );
    }

    #[test]
    fn v03_certificate_missing_raw_bytes() {
        let mut b = valid_v03();
        b["verificationMaterial"]["certificate"] = serde_json::json!({});
        assert!(format_err(&b.to_string()).contains("'certificate' missing 'rawBytes'"));
    }

    #[test]
    fn v03_certificate_raw_bytes_not_base64() {
        let mut b = valid_v03();
        b["verificationMaterial"]["certificate"]["rawBytes"] = serde_json::json!("!!!nope!!!");
        assert!(format_err(&b.to_string()).contains("'certificate.rawBytes' is not valid base64"));
    }

    #[test]
    fn v03_x509_chain_certificates_not_an_array() {
        let mut b = valid_v03();
        let vm = b["verificationMaterial"].as_object_mut().unwrap();
        vm.remove("certificate");
        vm.insert(
            "x509CertificateChain".to_string(),
            serde_json::json!({ "certificates": "not an array" }),
        );
        assert!(
            format_err(&b.to_string())
                .contains("'x509CertificateChain.certificates' is not an array")
        );
    }

    #[test]
    fn v03_x509_chain_entry_missing_raw_bytes() {
        let mut b = valid_v03();
        let vm = b["verificationMaterial"].as_object_mut().unwrap();
        vm.remove("certificate");
        vm.insert(
            "x509CertificateChain".to_string(),
            serde_json::json!({ "certificates": [{ "notRawBytes": "x" }] }),
        );
        let msg = format_err(&b.to_string());
        assert!(
            msg.contains("v0.3 certificate missing 'rawBytes'"),
            "expected the per-entry missing-rawBytes error, got: {msg}"
        );
    }

    #[test]
    fn v03_x509_chain_entry_raw_bytes_not_base64() {
        let mut b = valid_v03();
        let vm = b["verificationMaterial"].as_object_mut().unwrap();
        vm.remove("certificate");
        vm.insert(
            "x509CertificateChain".to_string(),
            serde_json::json!({ "certificates": [
                { "rawBytes": BASE64.encode([1u8, 2, 3]) },
                { "rawBytes": "!!!nope!!!" },
            ]}),
        );
        let msg = format_err(&b.to_string());
        assert!(
            msg.contains("v0.3 certificate 'rawBytes' is not valid base64"),
            "a bad cert ANYWHERE in the chain must fail, not just the leaf; got: {msg}"
        );
    }

    #[test]
    fn v03_no_certificate_at_all() {
        let mut b = valid_v03();
        b["verificationMaterial"]
            .as_object_mut()
            .unwrap()
            .remove("certificate");
        assert!(
            format_err(&b.to_string()).contains("no certificate in verificationMaterial"),
            "with neither certificate, x509CertificateChain, nor publicKey"
        );
    }

    #[test]
    fn v03_missing_message_signature() {
        let mut b = valid_v03();
        b["messageSignature"]
            .as_object_mut()
            .unwrap()
            .remove("signature");
        assert!(format_err(&b.to_string()).contains("missing 'messageSignature.signature'"));
    }

    #[test]
    fn v03_message_signature_not_base64() {
        let mut b = valid_v03();
        b["messageSignature"]["signature"] = serde_json::json!("!!!nope!!!");
        assert!(
            format_err(&b.to_string()).contains("'messageSignature.signature' is not valid base64")
        );
    }

    #[test]
    fn v03_missing_message_digest() {
        let mut b = valid_v03();
        b["messageSignature"]["messageDigest"]
            .as_object_mut()
            .unwrap()
            .remove("digest");
        assert!(
            format_err(&b.to_string()).contains("missing 'messageSignature.messageDigest.digest'")
        );
    }

    #[test]
    fn v03_digest_neither_hex_nor_base64() {
        let mut b = valid_v03();
        b["messageSignature"]["messageDigest"]["digest"] = serde_json::json!("!!!nope!!!");
        assert!(
            format_err(&b.to_string())
                .contains("messageDigest.digest is neither 64-char hex nor base64")
        );
    }

    #[test]
    fn v03_digest_wrong_length() {
        let mut b = valid_v03();
        // Valid base64, decodes to 3 bytes — not a SHA-256.
        b["messageSignature"]["messageDigest"]["digest"] =
            serde_json::json!(BASE64.encode([1u8, 2, 3]));
        assert!(
            format_err(&b.to_string()).contains("messageDigest.digest is 3 bytes, expected 32")
        );
    }

    #[test]
    fn v03_missing_or_empty_tlog_entries() {
        // Key absent entirely.
        let mut b = valid_v03();
        b["verificationMaterial"]
            .as_object_mut()
            .unwrap()
            .remove("tlogEntries");
        assert!(format_err(&b.to_string()).contains("no transparency-log entries"));

        // Present but empty — `.first()` yields None, same branch. A bundle
        // with zero log entries must be rejected, not accepted with a blank
        // Rekor entry.
        let mut b = valid_v03();
        b["verificationMaterial"]["tlogEntries"] = serde_json::json!([]);
        assert!(format_err(&b.to_string()).contains("no transparency-log entries"));
    }

    #[test]
    fn v03_tlog_log_index_not_an_integer() {
        let mut b = valid_v03();
        b["verificationMaterial"]["tlogEntries"][0]["logIndex"] = serde_json::json!(false);
        assert!(format_err(&b.to_string()).contains("v0.3 tlogEntry 'logIndex' is not an integer"));
    }

    #[test]
    fn v03_tlog_key_id_not_base64() {
        let mut b = valid_v03();
        b["verificationMaterial"]["tlogEntries"][0]["logId"]["keyId"] =
            serde_json::json!("!!!nope!!!");
        assert!(format_err(&b.to_string()).contains("tlogEntry 'logId.keyId' is not valid base64"));
    }

    #[test]
    fn v03_tlog_log_id_absent_yields_empty_log_id() {
        // Documented fallback (format.rs `None => String::new()`): an absent
        // `logId` is tolerated and produces an EMPTY log id rather than an
        // error. Asserted explicitly so the tolerance is visible: an empty
        // log_id cannot select a Rekor log key, so SET verification downstream
        // has nothing to check against.
        let mut b = valid_v03();
        b["verificationMaterial"]["tlogEntries"][0]
            .as_object_mut()
            .unwrap()
            .remove("logId");
        let sig = KeylessSignature::from_sigstore_bundle(&b.to_string())
            .expect("absent logId is currently tolerated");
        assert_eq!(sig.rekor_entry.log_id, "");
    }

    #[test]
    fn v03_tlog_integrated_time_not_a_number() {
        let mut b = valid_v03();
        b["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = serde_json::json!([1, 2]);
        assert!(format_err(&b.to_string()).contains("integratedTime is not an integer"));
    }

    // --- helper functions -------------------------------------------

    #[test]
    fn module_hash_from_body_rejects_non_base64() {
        let err = module_hash_from_hashedrekord_body("!!!not base64!!!").unwrap_err();
        assert!(format!("{err:?}").contains("Rekor body is not valid base64"));
    }

    #[test]
    fn module_hash_from_body_rejects_non_json() {
        let err =
            module_hash_from_hashedrekord_body(&BASE64.encode("not json at all")).unwrap_err();
        assert!(format!("{err:?}").contains("Rekor body is not valid JSON"));
    }

    #[test]
    fn module_hash_from_body_rejects_missing_hash_value() {
        let body = BASE64.encode(serde_json::json!({ "spec": { "data": {} } }).to_string());
        let err = module_hash_from_hashedrekord_body(&body).unwrap_err();
        assert!(format!("{err:?}").contains("Rekor body missing 'spec.data.hash.value'"));
    }

    #[test]
    fn module_hash_from_body_rejects_non_hex_value() {
        let body = BASE64.encode(
            serde_json::json!({ "spec": { "data": { "hash": { "value": "zz".repeat(32) } } } })
                .to_string(),
        );
        let err = module_hash_from_hashedrekord_body(&body).unwrap_err();
        assert!(format!("{err:?}").contains("Rekor body hash value is not valid hex"));
    }

    #[test]
    fn module_hash_from_body_rejects_wrong_length_hash() {
        // Valid hex, but 16 bytes rather than a SHA-256's 32. A short digest
        // must be rejected outright: it can never match a recomputed module
        // hash, and accepting it would let a truncated digest through.
        let body = BASE64.encode(
            serde_json::json!({ "spec": { "data": { "hash": { "value": "ab".repeat(16) } } } })
                .to_string(),
        );
        let err = module_hash_from_hashedrekord_body(&body).unwrap_err();
        assert!(
            format!("{err:?}").contains("Rekor body hash is 16 bytes, expected 32"),
            "got: {err:?}"
        );
    }

    #[test]
    fn decode_v03_digest_accepts_both_wire_encodings() {
        let raw: Vec<u8> = (0..32u8).collect();
        // wsc-emitted hex form.
        assert_eq!(decode_v03_digest(&hex::encode(&raw)).unwrap(), raw);
        // cosign wire form (base64) — 44 chars, so it takes the other arm.
        assert_eq!(decode_v03_digest(&BASE64.encode(&raw)).unwrap(), raw);
    }

    #[test]
    fn decode_v03_digest_rejects_garbage_and_wrong_length() {
        assert!(
            format!("{:?}", decode_v03_digest("!!!").unwrap_err())
                .contains("neither 64-char hex nor base64")
        );
        // Valid base64 of 31 bytes: decodes fine, wrong size.
        let short = BASE64.encode(vec![0u8; 31]);
        assert!(
            format!("{:?}", decode_v03_digest(&short).unwrap_err())
                .contains("messageDigest.digest is 31 bytes, expected 32")
        );
        // A 64-char string that is valid base64 but NOT hex (48 bytes encode
        // to exactly 64 unpadded base64 chars) must take the base64 arm and
        // decode to 48 bytes — proving the hex arm is gated on
        // `is_ascii_hexdigit`, not on length alone.
        let sixty_four_non_hex = BASE64.encode(vec![0xffu8; 48]);
        assert_eq!(sixty_four_non_hex.len(), 64);
        assert!(!sixty_four_non_hex.bytes().all(|b| b.is_ascii_hexdigit()));
        let err = decode_v03_digest(&sixty_four_non_hex).unwrap_err();
        assert!(
            format!("{err:?}").contains("messageDigest.digest is 48 bytes, expected 32"),
            "got: {err:?}"
        );
    }

    #[test]
    fn integrated_time_rejects_non_integer() {
        let err = integrated_time_to_rfc3339(&serde_json::json!("not a time")).unwrap_err();
        assert!(format!("{err:?}").contains("integratedTime is not an integer"));
        let err = integrated_time_to_rfc3339(&serde_json::json!(null)).unwrap_err();
        assert!(format!("{err:?}").contains("integratedTime is not an integer"));
    }

    #[test]
    fn integrated_time_rejects_out_of_range() {
        let err = integrated_time_to_rfc3339(&serde_json::json!(i64::MAX)).unwrap_err();
        assert!(
            format!("{err:?}").contains("is out of range"),
            "got: {err:?}"
        );
    }

    #[test]
    fn integrated_time_accepts_number_and_decimal_string() {
        // Both wire forms map to the SAME RFC3339 instant. `verify_cert_chain`
        // parses this field with `parse_from_rfc3339`, so a bare Unix-seconds
        // string here would break every ingested bundle.
        assert_eq!(
            integrated_time_to_rfc3339(&serde_json::json!(1_787_295_161i64)).unwrap(),
            "2026-08-21T06:52:41Z"
        );
        assert_eq!(
            integrated_time_to_rfc3339(&serde_json::json!("1787295161")).unwrap(),
            "2026-08-21T06:52:41Z"
        );
    }

    #[test]
    fn split_pem_certificates_handles_one_many_and_unterminated() {
        let one = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
        assert_eq!(split_pem_certificates(one).len(), 1);

        // Two concatenated blocks -> two chain entries (Fulcio leaf +
        // intermediate arrive this way in the legacy `cert` field).
        let two = format!("{one}{one}");
        let split = split_pem_certificates(&two);
        assert_eq!(split.len(), 2, "concatenated PEM blocks must be split");
        assert!(
            split
                .iter()
                .all(|c| c.ends_with("-----END CERTIFICATE-----"))
        );

        // No END marker at all: the whole trimmed input is returned as a
        // single entry rather than yielding an empty chain, which would make
        // an unterminated PEM silently look like "no certificate".
        let unterminated = "  -----BEGIN CERTIFICATE-----\nAQID  ";
        let split = split_pem_certificates(unterminated);
        assert_eq!(split, vec![unterminated.trim().to_string()]);
    }

    fn create_test_signature() -> KeylessSignature {
        let signature = vec![1, 2, 3, 4, 5];
        let cert_chain = vec![
            "-----BEGIN CERTIFICATE-----\ntest cert 1\n-----END CERTIFICATE-----".to_string(),
            "-----BEGIN CERTIFICATE-----\ntest cert 2\n-----END CERTIFICATE-----".to_string(),
        ];
        let rekor_entry = RekorEntry {
            uuid: "test-uuid-1234".to_string(),
            log_index: 42,
            body: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            log_id: "test-log-id".to_string(),
            inclusion_proof: vec![10, 20, 30, 40],
            signed_entry_timestamp: "c2lnbmF0dXJl".to_string(),
            integrated_time: "2024-01-01T00:00:00Z".to_string(),
        };
        let module_hash = vec![0xde, 0xad, 0xbe, 0xef];

        KeylessSignature::new(signature, cert_chain, rekor_entry, module_hash)
    }

    #[test]
    fn test_serialization_roundtrip() {
        let sig = create_test_signature();

        // Serialize to bytes
        let bytes = sig.to_bytes().expect("Serialization failed");

        // Verify format markers
        assert_eq!(bytes[0], KEYLESS_VERSION);
        assert_eq!(bytes[1], KEYLESS_SIG_TYPE);

        // Deserialize back
        let deserialized = KeylessSignature::from_bytes(&bytes).expect("Deserialization failed");

        // Verify all fields match
        assert_eq!(deserialized.signature, sig.signature);
        assert_eq!(deserialized.cert_chain, sig.cert_chain);
        assert_eq!(deserialized.rekor_entry.uuid, sig.rekor_entry.uuid);
        assert_eq!(
            deserialized.rekor_entry.log_index,
            sig.rekor_entry.log_index
        );
        assert_eq!(
            deserialized.rekor_entry.inclusion_proof,
            sig.rekor_entry.inclusion_proof
        );
        assert_eq!(
            deserialized.rekor_entry.integrated_time,
            sig.rekor_entry.integrated_time
        );
        assert_eq!(deserialized.module_hash, sig.module_hash);
    }

    #[test]
    fn test_empty_cert_chain() {
        let mut sig = create_test_signature();
        sig.cert_chain = vec![];

        let bytes = sig.to_bytes().expect("Serialization should succeed");
        let deserialized =
            KeylessSignature::from_bytes(&bytes).expect("Deserialization should succeed");

        assert_eq!(deserialized.cert_chain.len(), 0);
    }

    #[test]
    fn test_single_cert_chain() {
        let mut sig = create_test_signature();
        sig.cert_chain =
            vec!["-----BEGIN CERTIFICATE-----\nsingle\n-----END CERTIFICATE-----".to_string()];

        let bytes = sig.to_bytes().expect("Serialization should succeed");
        let deserialized =
            KeylessSignature::from_bytes(&bytes).expect("Deserialization should succeed");

        assert_eq!(deserialized.cert_chain.len(), 1);
        assert_eq!(deserialized.cert_chain[0], sig.cert_chain[0]);
    }

    #[test]
    fn test_max_cert_chain() {
        let mut sig = create_test_signature();
        // Create 255 certificates (max allowed)
        sig.cert_chain = (0..255)
            .map(|i| {
                format!(
                    "-----BEGIN CERTIFICATE-----\ncert {}\n-----END CERTIFICATE-----",
                    i
                )
            })
            .collect();

        let bytes = sig.to_bytes().expect("Serialization should succeed");
        let deserialized =
            KeylessSignature::from_bytes(&bytes).expect("Deserialization should succeed");

        assert_eq!(deserialized.cert_chain.len(), 255);
    }

    #[test]
    fn test_too_many_certs() {
        let mut sig = create_test_signature();
        // Create 256 certificates (one too many)
        sig.cert_chain = (0..256)
            .map(|i| {
                format!(
                    "-----BEGIN CERTIFICATE-----\ncert {}\n-----END CERTIFICATE-----",
                    i
                )
            })
            .collect();

        let result = sig.to_bytes();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WSError::KeylessFormatError(_)
        ));
    }

    #[test]
    fn test_invalid_version() {
        let sig = create_test_signature();
        let mut bytes = sig.to_bytes().expect("Serialization failed");

        // Corrupt version byte
        bytes[0] = 0xFF;

        let result = KeylessSignature::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WSError::KeylessFormatError(_)
        ));
    }

    #[test]
    fn test_invalid_signature_type() {
        let sig = create_test_signature();
        let mut bytes = sig.to_bytes().expect("Serialization failed");

        // Corrupt signature type byte
        bytes[1] = STANDARD_SIG_TYPE;

        let result = KeylessSignature::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WSError::KeylessFormatError(_)
        ));
    }

    #[test]
    fn test_truncated_data() {
        let sig = create_test_signature();
        let bytes = sig.to_bytes().expect("Serialization failed");

        // Try to deserialize truncated data
        let truncated = &bytes[0..5];
        let result = KeylessSignature::from_bytes(truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_rekor_entry_json_serialization() {
        let entry = RekorEntry {
            uuid: "test-uuid".to_string(),
            log_index: 123,
            body: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            log_id: "test-log-id".to_string(),
            inclusion_proof: vec![1, 2, 3],
            signed_entry_timestamp: "c2lnbmF0dXJl".to_string(),
            integrated_time: "2024-01-01T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&entry).expect("JSON serialization failed");
        let deserialized: RekorEntry =
            serde_json::from_str(&json).expect("JSON deserialization failed");

        assert_eq!(deserialized.uuid, entry.uuid);
        assert_eq!(deserialized.log_index, entry.log_index);
        assert_eq!(deserialized.body, entry.body);
        assert_eq!(deserialized.log_id, entry.log_id);
        assert_eq!(deserialized.inclusion_proof, entry.inclusion_proof);
        assert_eq!(
            deserialized.signed_entry_timestamp,
            entry.signed_entry_timestamp
        );
        assert_eq!(deserialized.integrated_time, entry.integrated_time);
    }

    #[test]
    fn test_verify_cert_chain_rejects_invalid() {
        let sig = create_test_signature();
        // Real implementation should reject fake test certificates
        // (create_test_signature uses dummy PEM data, not real Fulcio certs)
        assert!(sig.verify_cert_chain().is_err());

        // Empty chain should also be rejected
        let mut empty_sig = sig.clone();
        empty_sig.cert_chain = vec![];
        assert!(empty_sig.verify_cert_chain().is_err());
    }

    #[test]
    fn test_verify_rekor_inclusion_rejects_invalid() {
        let sig = create_test_signature();
        // The test data has invalid Rekor entry, so verification should fail
        // This proves that real verification is happening (not just a stub)
        let result = sig.verify_rekor_inclusion();
        assert!(
            result.is_err(),
            "Expected verification to fail with invalid test data"
        );

        // Verify we get a Rekor error (not some other error type)
        match result {
            Err(WSError::RekorError(_)) => {} // Expected
            Err(e) => panic!("Expected RekorError, got: {:?}", e),
            Ok(_) => panic!("Expected verification to fail"),
        }
    }

    #[test]
    fn test_verify_rekor_inclusion_rejects_missing_proof() {
        // Fail-closed building block for UCA-1 (#137): `verify_rekor_inclusion`
        // rejects an entry that carries no inclusion proof. NOTE: this method
        // is not yet wired into the production verify() path — it is blocked on
        // a verifier bug against current (Rekor v2) production proofs. This test
        // guards the fail-closed contract for when it is enabled.
        let mut sig = create_test_signature();
        sig.rekor_entry.inclusion_proof = vec![];
        match sig.verify_rekor_inclusion() {
            Err(WSError::RekorError(msg)) => {
                assert!(
                    msg.contains("Missing inclusion proof"),
                    "expected a missing-proof error, got: {msg}"
                );
            }
            Err(e) => panic!("Expected RekorError(Missing inclusion proof), got: {:?}", e),
            Ok(_) => panic!("Expected fail-closed rejection of a missing inclusion proof"),
        }
    }

    #[test]
    fn test_get_identity_no_certs() {
        let mut sig = create_test_signature();
        sig.cert_chain = vec![];

        let result = sig.get_identity();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::CertificateError(_)));
    }

    #[test]
    fn test_get_issuer_no_certs() {
        let mut sig = create_test_signature();
        sig.cert_chain = vec![];

        let result = sig.get_issuer();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::CertificateError(_)));
    }

    #[test]
    fn test_large_signature() {
        let mut sig = create_test_signature();
        // Create a large signature (64 bytes, typical for Ed25519)
        sig.signature = vec![0x42; 64];

        let bytes = sig.to_bytes().expect("Serialization failed");
        let deserialized = KeylessSignature::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(deserialized.signature.len(), 64);
        assert_eq!(deserialized.signature, sig.signature);
    }

    #[test]
    fn test_verify_cert_chain_rejects_too_deep() {
        // A 100-cert synthetic chain must be rejected before any x509 parsing.
        // This exercises the MAX_CHAIN_DEPTH guard in verify_cert_chain.
        let mut sig = create_test_signature();
        sig.cert_chain = (0..100)
            .map(|i| {
                format!(
                    "-----BEGIN CERTIFICATE-----\nfake-cert-{}\n-----END CERTIFICATE-----",
                    i
                )
            })
            .collect();

        let result = sig.verify_cert_chain();
        match result {
            Err(WSError::ChainTooDeep(max)) => assert_eq!(max, MAX_CHAIN_DEPTH),
            Err(other) => panic!("expected ChainTooDeep, got {:?}", other),
            Ok(_) => panic!("expected ChainTooDeep, got Ok"),
        }
    }

    #[test]
    fn test_verify_cert_chain_at_max_depth_proceeds_to_parser() {
        // A chain of MAX_CHAIN_DEPTH bogus PEMs must NOT be rejected by the
        // depth check; it should fall through to PEM/X.509 parsing and fail
        // there. This proves the bound is at MAX_CHAIN_DEPTH+1, not below.
        let mut sig = create_test_signature();
        sig.cert_chain = (0..MAX_CHAIN_DEPTH)
            .map(|i| {
                format!(
                    "-----BEGIN CERTIFICATE-----\nfake-cert-{}\n-----END CERTIFICATE-----",
                    i
                )
            })
            .collect();

        let result = sig.verify_cert_chain();
        // Must not be rejected by depth guard
        assert!(!matches!(result, Err(WSError::ChainTooDeep(_))));
        // But it must still fail (these aren't real Fulcio certs)
        assert!(result.is_err());
    }

    #[test]
    fn test_large_module_hash() {
        let mut sig = create_test_signature();
        // Create a SHA-256 hash (32 bytes)
        sig.module_hash = vec![0xFF; 32];

        let bytes = sig.to_bytes().expect("Serialization failed");
        let deserialized = KeylessSignature::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(deserialized.module_hash.len(), 32);
        assert_eq!(deserialized.module_hash, sig.module_hash);
    }

    // -----------------------------------------------------------------
    // Artifact-binding tests for issue #135
    //
    // These tests reproduce the class of tampering the original verifier
    // accepted (signature blob present and well-formed, but the artifact
    // bytes don't match what the cert holder actually signed). Each test
    // builds a real cert with a real ECDSA P-256 keypair, signs a real
    // module, then mutates one piece of the bundle and asserts rejection.
    // -----------------------------------------------------------------

    /// Test fixture: a real WASM module + a KeylessSignature whose cert,
    /// signature, and module_hash all consistently bind to that module.
    /// Calling [`verify_artifact_binding`] on `(signed_module, keyless_sig)`
    /// must succeed; tamper any one piece and it must fail.
    struct ArtifactBindingFixture {
        signed_module: crate::Module,
        keyless_sig: KeylessSignature,
        /// A second, independently-generated cert chain (with a different
        /// public key) for the "swap the cert" tamper test.
        other_cert_pem: String,
    }

    fn build_artifact_binding_fixture() -> ArtifactBindingFixture {
        use crate::wasm_module::{Module, Section, StandardSection, SectionId};
        use ecdsa::signature::DigestSigner;
        use p256::pkcs8::DecodePrivateKey;

        // 1. Build a realistic-enough module: WASM magic + version, plus a
        // standard section so the hash covers more than just the header.
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(
                    SectionId::Type,
                    vec![0x01, 0x60, 0x00, 0x00],
                )),
                Section::Standard(StandardSection::new(
                    SectionId::Function,
                    vec![0x01, 0x00],
                )),
                Section::Standard(StandardSection::new(
                    SectionId::Code,
                    vec![0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b],
                )),
            ],
        };

        // 2. Generate an ECDSA P-256 keypair via rcgen, then re-import the
        // PKCS#8 PEM into p256 so we can both (a) mint a real cert that
        // embeds the public key and (b) sign the module hash with the
        // matching private key. Going rcgen→p256 avoids hand-rolling
        // PKCS#8 export from p256.
        let cert_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("rcgen keypair generation");
        let signing_key_pem = cert_keypair.serialize_pem();
        let secret = p256::SecretKey::from_pkcs8_pem(&signing_key_pem)
            .expect("p256 import of rcgen PKCS8 PEM");
        let signing_key = ecdsa::SigningKey::<p256::NistP256>::from(&secret);

        let params = rcgen::CertificateParams::new(vec!["fixture.local".to_string()])
            .expect("cert params");
        let cert = params.self_signed(&cert_keypair).expect("self-signed cert");
        let cert_pem = cert.pem();

        // 3. Sign the module hash exactly the way `KeylessSigner::sign_module` does.
        let mut module_bytes = Vec::new();
        module
            .clone()
            .serialize(&mut module_bytes)
            .expect("module serialize");

        let mut hasher = Sha256::new();
        hasher.update(&module_bytes);
        let signature: p256::ecdsa::Signature = signing_key.sign_digest(hasher.clone());
        let module_hash = hasher.finalize().to_vec();

        // 4. Build the hashedrekord body matching the bundle so the
        // Rekor body-binding check has a real document to validate.
        // The signer side at `rekor.rs::upload_entry` constructs this
        // exact shape; we mirror it byte-for-byte.
        let sig_bytes_vec = signature.to_bytes().to_vec();
        let body_json = build_hashedrekord_body(&sig_bytes_vec, &cert_pem, &module_hash);

        let rekor_entry = RekorEntry {
            uuid: "fixture-rekor-uuid".to_string(),
            log_index: 1,
            body: body_json,
            log_id: "fixture-log-id".to_string(),
            inclusion_proof: vec![],
            signed_entry_timestamp: String::new(),
            integrated_time: "2026-01-01T00:00:00Z".to_string(),
        };
        let keyless_sig = KeylessSignature::new(
            sig_bytes_vec,
            vec![cert_pem.clone()],
            rekor_entry,
            module_hash,
        );

        let sig_blob = keyless_sig.to_bytes().expect("keyless sig serialize");
        let signed_module = module.attach_signature(&sig_blob).expect("attach signature");

        // 5. Mint an unrelated cert with a different keypair for the
        // cert-substitution test.
        let other_keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("other keypair");
        let other_params = rcgen::CertificateParams::new(vec!["other.local".to_string()])
            .expect("other params");
        let other_cert = other_params
            .self_signed(&other_keypair)
            .expect("other self-signed");

        ArtifactBindingFixture {
            signed_module,
            keyless_sig,
            other_cert_pem: other_cert.pem(),
        }
    }

    /// Build a `hashedrekord/0.0.1` body JSON matching the inputs and
    /// return it base64-encoded (as the Rekor API returns it).
    fn build_hashedrekord_body(
        signature_bytes: &[u8],
        leaf_cert_pem: &str,
        module_hash: &[u8],
    ) -> String {
        let body = serde_json::json!({
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "content": BASE64.encode(signature_bytes),
                    "publicKey": {
                        "content": BASE64.encode(leaf_cert_pem.as_bytes()),
                    },
                },
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": hex::encode(module_hash),
                    },
                },
            },
        });
        BASE64.encode(serde_json::to_vec(&body).expect("body to JSON"))
    }

    #[test]
    fn test_verify_artifact_binding_accepts_genuine_signed_module() {
        let fx = build_artifact_binding_fixture();
        fx.keyless_sig
            .verify_artifact_binding(&fx.signed_module)
            .expect("genuine signed module must verify");
    }

    /// Reproduces issue #135 exactly: flip a byte inside the signed
    /// payload (not in the signature section), keep the signature blob
    /// intact, assert verification rejects.
    #[test]
    fn test_verify_artifact_binding_rejects_byte_flipped_module() {
        use crate::wasm_module::{Section, SectionLike, StandardSection};

        let fx = build_artifact_binding_fixture();

        // Tamper a byte inside the Code section's payload — well outside
        // the signature custom section, so the signature blob still
        // parses and the cert/Rekor checks would still succeed. We
        // rebuild the section (rather than mutating in place) because
        // `StandardSection`'s fields are private.
        let tampered_sections: Vec<Section> = fx
            .signed_module
            .sections
            .iter()
            .map(|s| match s {
                Section::Standard(std_sec) if std_sec.id() == crate::SectionId::Code => {
                    let mut payload = std_sec.payload().to_vec();
                    assert!(!payload.is_empty(), "Code section has bytes");
                    payload[0] ^= 0xFF;
                    Section::Standard(StandardSection::new(std_sec.id(), payload))
                }
                other => other.clone(),
            })
            .collect();
        let tampered = crate::Module {
            header: fx.signed_module.header,
            sections: tampered_sections,
        };

        let err = fx
            .keyless_sig
            .verify_artifact_binding(&tampered)
            .expect_err("tampered module must be rejected");
        assert!(
            matches!(err, WSError::VerificationFailed),
            "expected VerificationFailed, got: {:?}",
            err
        );
    }

    /// Tampering the signature blob (not the artifact) must also be
    /// rejected — proves the ECDSA verify leg fires even when the hash
    /// check would pass.
    #[test]
    fn test_verify_artifact_binding_rejects_corrupted_signature() {
        let fx = build_artifact_binding_fixture();
        let mut tampered_sig = fx.keyless_sig.clone();
        // Flip the high bit of the first signature byte — keeps the
        // length valid (so `Signature::from_slice` succeeds) but breaks
        // the cryptographic check.
        tampered_sig.signature[0] ^= 0x80;

        let err = tampered_sig
            .verify_artifact_binding(&fx.signed_module)
            .expect_err("corrupted signature must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    /// Pre-image attack: keep the real signature, swap the stored
    /// `module_hash` to whatever the attacker wants the verifier to
    /// recompute over. The hash check passes (we tampered the field to
    /// match), but the ECDSA verify must still reject — because
    /// `signature` was made over the genuine hash, not the substituted
    /// one. This protects against an attacker who can recompute hashes
    /// but not forge ECDSA signatures.
    #[test]
    fn test_verify_artifact_binding_rejects_substituted_module_hash() {
        let fx = build_artifact_binding_fixture();
        let mut tampered_sig = fx.keyless_sig.clone();
        tampered_sig.module_hash = vec![0xAA; 32];

        let err = tampered_sig
            .verify_artifact_binding(&fx.signed_module)
            .expect_err("hash substitution must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    /// Replace the leaf cert with an unrelated valid cert (different
    /// keypair). The hash check passes (artifact unchanged), but ECDSA
    /// verify under the new public key must fail.
    #[test]
    fn test_verify_artifact_binding_rejects_substituted_cert() {
        let fx = build_artifact_binding_fixture();
        let mut tampered_sig = fx.keyless_sig.clone();
        tampered_sig.cert_chain = vec![fx.other_cert_pem.clone()];

        let err = tampered_sig
            .verify_artifact_binding(&fx.signed_module)
            .expect_err("cert substitution must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    /// If the module has no signature section at all,
    /// `verify_artifact_binding` must surface that as `NoSignatures`
    /// rather than silently passing or returning a confusing error.
    #[test]
    fn test_verify_artifact_binding_rejects_module_without_signature_section() {
        let fx = build_artifact_binding_fixture();
        let (unsigned_module, _) = fx
            .signed_module
            .clone()
            .detach_signature()
            .expect("fixture is signed");

        let err = fx
            .keyless_sig
            .verify_artifact_binding(&unsigned_module)
            .expect_err("unsigned module must be rejected");
        assert!(
            matches!(err, WSError::NoSignatures),
            "expected NoSignatures, got: {:?}",
            err
        );
    }

    /// Empty cert chain must be rejected (defense in depth — the chain
    /// check in `verify()` already catches this, but the binding method
    /// is a public API and must fail-closed independently).
    #[test]
    fn test_verify_artifact_binding_rejects_empty_cert_chain() {
        let fx = build_artifact_binding_fixture();
        let mut tampered_sig = fx.keyless_sig.clone();
        tampered_sig.cert_chain.clear();

        let err = tampered_sig
            .verify_artifact_binding(&fx.signed_module)
            .expect_err("empty cert chain must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    // -----------------------------------------------------------------
    // Rekor body-binding tests for issue #135 UCA-2
    //
    // verify_artifact_binding (above) closes the "cert+sig+module
    // mutually consistent" gap. These tests close the orthogonal gap:
    // the embedded Rekor entry's `body` must actually reference *this*
    // bundle. Each test takes the fully-bound fixture, mutates one
    // field of the body (artifact hash, signature, or public key), and
    // asserts rejection.
    // -----------------------------------------------------------------

    /// Re-encode a hashedrekord body after applying a mutation to its
    /// JSON value. Returns the new base64-encoded body string.
    fn remunge_body<F: FnOnce(&mut serde_json::Value)>(body_b64: &str, mutate: F) -> String {
        let raw = BASE64.decode(body_b64).expect("body is base64");
        let mut body: serde_json::Value = serde_json::from_slice(&raw).expect("body is JSON");
        mutate(&mut body);
        BASE64.encode(serde_json::to_vec(&body).expect("body to JSON"))
    }

    #[test]
    fn test_verify_rekor_body_binding_accepts_consistent_body() {
        let fx = build_artifact_binding_fixture();
        fx.keyless_sig
            .verify_rekor_body_binds_to_bundle()
            .expect("consistent hashedrekord body must verify");
    }

    /// Attacker takes a legitimately-signed module's signature blob but
    /// embeds an unrelated Rekor entry that logged a *different* artifact.
    /// `verify_artifact_binding` accepts the bundle (cert+sig+module are
    /// self-consistent), but the body's `data.hash.value` does not
    /// match the bundle's `module_hash` — must reject.
    #[test]
    fn test_verify_rekor_body_binding_rejects_artifact_hash_mismatch() {
        let fx = build_artifact_binding_fixture();
        let mut tampered = fx.keyless_sig.clone();
        tampered.rekor_entry.body = remunge_body(&tampered.rekor_entry.body, |body| {
            body["spec"]["data"]["hash"]["value"] = serde_json::json!(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            );
        });

        let err = tampered
            .verify_rekor_body_binds_to_bundle()
            .expect_err("body artifact-hash mismatch must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    /// Body's recorded signature differs from the bundle's signature —
    /// catches the case where an attacker borrows a Rekor entry whose
    /// logged signature came from a different signing event over the
    /// same hash.
    #[test]
    fn test_verify_rekor_body_binding_rejects_signature_mismatch() {
        let fx = build_artifact_binding_fixture();
        let mut tampered = fx.keyless_sig.clone();
        tampered.rekor_entry.body = remunge_body(&tampered.rekor_entry.body, |body| {
            // Substitute a different base64 blob of the same length.
            let bogus = BASE64.encode(vec![0x42u8; 64]);
            body["spec"]["signature"]["content"] = serde_json::json!(bogus);
        });

        let err = tampered
            .verify_rekor_body_binds_to_bundle()
            .expect_err("body signature mismatch must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    /// Body's recorded public key refers to a different cert than the
    /// bundle's leaf — catches the case where an attacker borrows a
    /// Rekor entry that logged a different identity's signature over
    /// the same hash and signature blob.
    #[test]
    fn test_verify_rekor_body_binding_rejects_public_key_mismatch() {
        let fx = build_artifact_binding_fixture();
        let mut tampered = fx.keyless_sig.clone();
        let other_pubkey_b64 = BASE64.encode(fx.other_cert_pem.as_bytes());
        tampered.rekor_entry.body = remunge_body(&tampered.rekor_entry.body, |body| {
            body["spec"]["signature"]["publicKey"]["content"] =
                serde_json::json!(other_pubkey_b64);
        });

        let err = tampered
            .verify_rekor_body_binds_to_bundle()
            .expect_err("body public-key mismatch must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    /// Unsupported kind / apiVersion / hash algorithm must reject —
    /// guards against future Rekor types whose semantics this verifier
    /// hasn't been taught to interpret.
    #[test]
    fn test_verify_rekor_body_binding_rejects_unsupported_kind() {
        let fx = build_artifact_binding_fixture();
        let mut tampered = fx.keyless_sig.clone();
        tampered.rekor_entry.body = remunge_body(&tampered.rekor_entry.body, |body| {
            body["kind"] = serde_json::json!("intoto");
        });

        let err = tampered
            .verify_rekor_body_binds_to_bundle()
            .expect_err("unsupported kind must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    #[test]
    fn test_verify_rekor_body_binding_rejects_unsupported_api_version() {
        let fx = build_artifact_binding_fixture();
        let mut tampered = fx.keyless_sig.clone();
        tampered.rekor_entry.body = remunge_body(&tampered.rekor_entry.body, |body| {
            body["apiVersion"] = serde_json::json!("99.0.0");
        });

        let err = tampered
            .verify_rekor_body_binds_to_bundle()
            .expect_err("unsupported apiVersion must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    #[test]
    fn test_verify_rekor_body_binding_rejects_non_sha256_hash_algorithm() {
        let fx = build_artifact_binding_fixture();
        let mut tampered = fx.keyless_sig.clone();
        tampered.rekor_entry.body = remunge_body(&tampered.rekor_entry.body, |body| {
            body["spec"]["data"]["hash"]["algorithm"] = serde_json::json!("md5");
        });

        let err = tampered
            .verify_rekor_body_binds_to_bundle()
            .expect_err("non-sha256 hash must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    /// Malformed inputs (non-base64 body, non-JSON body, malformed
    /// inner base64 fields) must fail-closed with the same error
    /// variant — never panic, never accept.
    #[test]
    fn test_verify_rekor_body_binding_rejects_garbage_body() {
        let fx = build_artifact_binding_fixture();
        let mut tampered = fx.keyless_sig.clone();
        tampered.rekor_entry.body = "this is not base64 either".to_string();

        let err = tampered
            .verify_rekor_body_binds_to_bundle()
            .expect_err("garbage body must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    #[test]
    fn test_verify_rekor_body_binding_rejects_non_json_body() {
        let fx = build_artifact_binding_fixture();
        let mut tampered = fx.keyless_sig.clone();
        tampered.rekor_entry.body = BASE64.encode(b"not json at all");

        let err = tampered
            .verify_rekor_body_binds_to_bundle()
            .expect_err("non-JSON body must be rejected");
        assert!(matches!(err, WSError::VerificationFailed));
    }

    /// Case-insensitivity check: Rekor sometimes returns hex hashes
    /// uppercase or mixed case. The check must accept those (genuine
    /// data) but still reject when bytes truly differ.
    #[test]
    fn test_verify_rekor_body_binding_accepts_uppercase_hex_hash() {
        let fx = build_artifact_binding_fixture();
        let mut tampered = fx.keyless_sig.clone();
        tampered.rekor_entry.body = remunge_body(&tampered.rekor_entry.body, |body| {
            let v = body["spec"]["data"]["hash"]["value"]
                .as_str()
                .unwrap()
                .to_ascii_uppercase();
            body["spec"]["data"]["hash"]["value"] = serde_json::json!(v);
        });

        tampered
            .verify_rekor_body_binds_to_bundle()
            .expect("uppercase hex hash must still verify");
    }
}
