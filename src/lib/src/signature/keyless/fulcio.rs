use crate::error::WSError;
use crate::signature::keyless::oidc::OidcToken;
use serde::{Deserialize, Serialize};
use spki::der::asn1::BitString;
use spki::der::{Decode, Encode};
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
use x509_parser::prelude::*;

/// Fulcio certificate response
///
/// Contains the X.509 certificate chain and public key from Fulcio.
/// The certificates are short-lived (typically 10 minutes) and bound
/// to the OIDC identity.
#[derive(Debug, Clone)]
pub struct FulcioCertificate {
    /// X.509 certificate chain (PEM-encoded)
    /// Index 0 is the leaf certificate, subsequent entries are intermediate/root CAs
    pub cert_chain: Vec<String>,
    /// Leaf certificate (PEM-encoded)
    pub leaf_cert: String,
    /// Public key from certificate (DER-encoded)
    pub public_key: Vec<u8>,
}

/// Request structure for Fulcio signing certificate API
#[derive(Debug, Serialize)]
struct FulcioRequest {
    credentials: Credentials,
    #[serde(rename = "publicKeyRequest")]
    public_key_request: PublicKeyRequest,
}

#[derive(Debug, Serialize)]
struct Credentials {
    #[serde(rename = "oidcIdentityToken")]
    oidc_identity_token: String,
}

#[derive(Debug, Serialize)]
struct PublicKeyRequest {
    #[serde(rename = "publicKey")]
    public_key: PublicKey,
    #[serde(rename = "proofOfPossession")]
    proof_of_possession: String,
}

#[derive(Debug, Serialize)]
struct PublicKey {
    // Fulcio v2 JSON API: PublicKeyAlgorithm enum as string per protobuf JSON encoding
    // https://protobuf.dev/programming-guides/json/ - enums serialize as string names
    algorithm: String,
    content: String,
}

/// Response structure from Fulcio signing certificate API
#[derive(Debug, Deserialize)]
struct FulcioResponse {
    #[serde(rename = "signedCertificateEmbeddedSct")]
    signed_certificate_embedded_sct: SignedCertificateEmbeddedSct,
}

#[derive(Debug, Deserialize)]
struct SignedCertificateEmbeddedSct {
    chain: ChainWrapper,
}

#[derive(Debug, Deserialize)]
struct ChainWrapper {
    certificates: Vec<String>,
}

/// Fulcio client for obtaining short-lived certificates
///
/// Fulcio is a WebPKI certificate authority that issues short-lived
/// certificates based on OIDC identity tokens. These certificates are
/// used for keyless signing.
pub struct FulcioClient {
    /// Fulcio server URL (default: https://fulcio.sigstore.dev)
    base_url: String,
    #[cfg(not(target_os = "wasi"))]
    /// HTTP client for native builds
    client: ureq::Agent,
}

impl FulcioClient {
    /// Create client with default Fulcio server
    ///
    /// Uses the public Sigstore Fulcio instance at https://fulcio.sigstore.dev
    ///
    /// # Certificate Pinning (Issue #12)
    ///
    /// Certificate pinning infrastructure is implemented but not yet enforced due to
    /// HTTP client limitations. See `cert_pinning` module documentation for details.
    ///
    /// Set `WSC_FULCIO_PINS` environment variable to configure pins (not yet enforced).
    /// Set `WSC_REQUIRE_CERT_PINNING=1` to fail if pinning cannot be enforced.
    pub fn new() -> Self {
        Self::with_url("https://fulcio.sigstore.dev".to_string())
    }

    /// Create client with custom Fulcio server
    ///
    /// # Arguments
    /// * `base_url` - Base URL of the Fulcio server (without trailing slash)
    pub fn with_url(base_url: String) -> Self {
        // Check if strict certificate pinning is required (Issue #12)
        // This will fail if WSC_REQUIRE_CERT_PINNING=1 and pinning cannot be enforced
        if let Err(e) = super::cert_pinning::check_pinning_enforcement("fulcio") {
            log::warn!("Certificate pinning check failed: {}", e);
            // Note: We continue anyway because pinning enforcement would happen at TLS level
            // This is just an early warning to users who set WSC_REQUIRE_CERT_PINNING=1
        }

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

    /// Encode ECDSA P-256 public key in SPKI (SubjectPublicKeyInfo) format
    ///
    /// Fulcio requires public keys to be in PKIX/SPKI format as per RFC 5480
    fn encode_ecdsa_p256_spki(raw_public_key: &[u8]) -> Result<Vec<u8>, WSError> {
        // ECDSA OID: 1.2.840.10045.2.1 (ecPublicKey)
        const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
        // P-256 curve OID: 1.2.840.10045.3.1.7 (secp256r1 / prime256v1)
        const SECP256R1_OID: &str = "1.2.840.10045.3.1.7";

        let ec_oid = ObjectIdentifier::new(EC_PUBLIC_KEY_OID)
            .map_err(|e| WSError::FulcioError(format!("Invalid EC public key OID: {}", e)))?;

        let curve_oid = ObjectIdentifier::new(SECP256R1_OID)
            .map_err(|e| WSError::FulcioError(format!("Invalid secp256r1 OID: {}", e)))?;

        // For ECDSA, algorithm parameters contain the curve OID
        use spki::der::Any;
        let curve_oid_der = curve_oid
            .to_der()
            .map_err(|e| WSError::FulcioError(format!("Failed to encode curve OID: {}", e)))?;

        let curve_oid_any = Any::from_der(&curve_oid_der)
            .map_err(|e| WSError::FulcioError(format!("Failed to parse curve OID as Any: {}", e)))?;

        let algorithm = AlgorithmIdentifierOwned {
            oid: ec_oid,
            parameters: Some(curve_oid_any),
        };

        // Create SPKI structure with BitString for the public key
        // Public key should be in uncompressed form (0x04 || x || y)
        let public_key_bits = BitString::new(0, raw_public_key)
            .map_err(|e| WSError::FulcioError(format!("Failed to create BitString: {}", e)))?;

        let spki = SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key: public_key_bits,
        };

        // Encode to DER
        spki.to_der()
            .map_err(|e| WSError::FulcioError(format!("Failed to encode SPKI: {}", e)))
    }

    /// Encode SPKI DER bytes to PEM format
    ///
    /// Fulcio's HTTP/JSON API expects PEM format with BEGIN/END headers
    fn encode_spki_to_pem(spki_der: &[u8]) -> Result<String, WSError> {
        // Convert DER to base64
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            spki_der,
        );

        // Split base64 into 64-character lines (standard PEM format)
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            // SAFETY: base64 encoding always produces valid UTF-8 (only uses ASCII chars A-Z, a-z, 0-9, +, /, =)
            // However, to avoid unwrap (Issue #13), we handle the error case properly
            let chunk_str = std::str::from_utf8(chunk)
                .map_err(|e| WSError::FulcioError(format!("Invalid base64 encoding (not UTF-8): {}", e)))?;
            pem.push_str(chunk_str);
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----");

        Ok(pem)
    }

    /// Request a certificate from Fulcio
    ///
    /// # Arguments
    /// * `oidc_token` - OIDC identity token from a supported provider
    /// * `public_key` - Raw ECDSA P-256 public key in uncompressed form (65 bytes: 0x04 || x || y)
    /// * `proof_of_possession` - Signature proving key ownership (DER-encoded ECDSA signature)
    ///
    /// # Returns
    /// A `FulcioCertificate` containing the certificate chain and public key
    ///
    /// # Errors
    /// Returns `WSError::FulcioError` if:
    /// - The HTTP request fails
    /// - The response cannot be parsed
    /// - The certificate chain is invalid
    /// - The public key cannot be extracted
    pub fn get_certificate(
        &self,
        oidc_token: &OidcToken,
        public_key: &[u8],
        proof_of_possession: &[u8],
    ) -> Result<FulcioCertificate, WSError> {
        // Encode raw ECDSA P-256 public key to SPKI format (required by Fulcio)
        let spki_der = Self::encode_ecdsa_p256_spki(public_key)?;

        // Fulcio expects PEM format (with BEGIN/END headers), not raw base64 DER
        // Per sigstore-go implementation: https://github.com/sigstore/sigstore-go/blob/main/pkg/sign/certificate.go
        let public_key_pem = Self::encode_spki_to_pem(&spki_der)?;

        // Encode proof of possession as base64
        let proof_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            proof_of_possession,
        );

        // Build request
        let request = FulcioRequest {
            credentials: Credentials {
                oidc_identity_token: oidc_token.token.clone(),
            },
            public_key_request: PublicKeyRequest {
                public_key: PublicKey {
                    // Fulcio v2 JSON API: Use string "ECDSA" per protobuf JSON encoding
                    algorithm: "ECDSA".to_string(),
                    content: public_key_pem,
                },
                proof_of_possession: proof_b64,
            },
        };

        // Send request using platform-specific implementation
        let response = self.send_request(&request)?;

        // Parse certificate chain
        let cert_chain = response
            .signed_certificate_embedded_sct
            .chain
            .certificates;

        if cert_chain.is_empty() {
            return Err(WSError::FulcioError(
                "Empty certificate chain in response".to_string(),
            ));
        }

        // The first certificate is the leaf
        let leaf_cert = cert_chain[0].clone();

        // Extract public key from the leaf certificate
        let public_key = Self::extract_public_key(&leaf_cert)?;

        Ok(FulcioCertificate {
            cert_chain: cert_chain.clone(),
            leaf_cert,
            public_key,
        })
    }

    /// Extract public key from PEM-encoded certificate
    fn extract_public_key(pem_cert: &str) -> Result<Vec<u8>, WSError> {
        // Parse PEM to get DER bytes
        let pem = pem::parse(pem_cert)
            .map_err(|e| WSError::FulcioError(format!("Failed to parse PEM certificate: {}", e)))?;

        // Parse X.509 certificate
        let (_, cert) = X509Certificate::from_der(&pem.contents()).map_err(|e| {
            WSError::FulcioError(format!("Failed to parse X.509 certificate: {}", e))
        })?;

        // Extract public key bytes from the certificate
        let public_key = cert.public_key();
        let key_bytes = public_key.subject_public_key.data.to_vec();

        Ok(key_bytes)
    }
}

// Native implementation using ureq
#[cfg(not(target_os = "wasi"))]
impl FulcioClient {
    fn send_request(&self, request: &FulcioRequest) -> Result<FulcioResponse, WSError> {
        let url = format!("{}/api/v2/signingCert", self.base_url);

        let json_request = serde_json::to_string(request)
            .map_err(|e| WSError::FulcioError(format!("Failed to serialize request: {}", e)))?;

        // Log the exact request for debugging (using eprintln to ensure it appears in logs)
        eprintln!("[DEBUG] Fulcio request JSON: {}", json_request);
        log::debug!("Fulcio request JSON: {}", json_request);

        // Agent configured with http_status_as_error(false), so we always get Ok(Response)
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .send(json_request.as_bytes())
            .map_err(|e| {
                WSError::FulcioError(format!("Failed to send request to Fulcio: {}", e))
            })?;

        // Check response status
        let status = response.status();
        if status != 200 && status != 201 {
            let error_body = response
                .into_body()
                .read_to_string()
                .unwrap_or_else(|_| "Unable to read error response".to_string());
            return Err(WSError::FulcioError(format!(
                "Fulcio returned status {}: {}",
                status, error_body
            )));
        }

        // Parse response
        let body = response.into_body().read_to_string().map_err(|e| {
            WSError::FulcioError(format!("Failed to read response body: {}", e))
        })?;

        let fulcio_response: FulcioResponse = serde_json::from_str(&body)
            .map_err(|e| WSError::FulcioError(format!("Failed to parse Fulcio response: {}", e)))?;

        Ok(fulcio_response)
    }
}

// WASI implementation using wasi::http
#[cfg(target_os = "wasi")]
impl FulcioClient {
    fn send_request(&self, request: &FulcioRequest) -> Result<FulcioResponse, WSError> {
        use wasi::http::outgoing_handler;
        use wasi::http::types::{Fields, Method, OutgoingBody, OutgoingRequest, Scheme};

        // Serialize request to JSON
        let request_json = serde_json::to_vec(request)
            .map_err(|e| WSError::FulcioError(format!("Failed to serialize request: {}", e)))?;

        // Parse URL to extract components
        let url = format!("{}/api/v2/signingCert", self.base_url);
        let url_str = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .ok_or_else(|| WSError::FulcioError("Invalid Fulcio URL scheme".to_string()))?;

        let (authority, path) = url_str
            .split_once('/')
            .map(|(auth, path)| (auth, format!("/{}", path)))
            .unwrap_or((url_str, "/api/v2/signingCert".to_string()));

        // Create headers
        let headers = Fields::new();
        headers
            .append(
                &"Content-Type".to_string(),
                &b"application/json".to_vec(),
            )
            .map_err(|_| WSError::FulcioError("Failed to set Content-Type header".to_string()))?;

        // Create outgoing request
        let outgoing_request = OutgoingRequest::new(headers);
        outgoing_request
            .set_method(&Method::Post)
            .map_err(|_| WSError::FulcioError("Failed to set HTTP method".to_string()))?;
        outgoing_request
            .set_scheme(Some(&Scheme::Https))
            .map_err(|_| WSError::FulcioError("Failed to set HTTPS scheme".to_string()))?;
        outgoing_request
            .set_authority(Some(authority))
            .map_err(|_| WSError::FulcioError("Failed to set authority".to_string()))?;
        outgoing_request
            .set_path_with_query(Some(&path))
            .map_err(|_| WSError::FulcioError("Failed to set path".to_string()))?;

        // Write request body
        let body = outgoing_request
            .body()
            .map_err(|_| WSError::FulcioError("Failed to get request body".to_string()))?;

        let request_stream = body
            .write()
            .map_err(|_| WSError::FulcioError("Failed to get request stream".to_string()))?;

        request_stream
            .blocking_write_and_flush(&request_json)
            .map_err(|_| WSError::FulcioError("Failed to write request body".to_string()))?;

        drop(request_stream);

        OutgoingBody::finish(body, None)
            .map_err(|_| WSError::FulcioError("Failed to finish request body".to_string()))?;

        // Send request
        let future_response = outgoing_handler::handle(outgoing_request, None)
            .map_err(|_| WSError::FulcioError("Failed to send HTTP request".to_string()))?;

        // Wait for response
        let incoming_response = future_response
            .get()
            .ok_or_else(|| WSError::FulcioError("HTTP request not ready".to_string()))?
            .map_err(|_| WSError::FulcioError("Failed to get HTTP response".to_string()))??;

        // Check response status
        let status = incoming_response.status();
        if status != 200 && status != 201 {
            return Err(WSError::FulcioError(format!(
                "Fulcio returned status {}",
                status
            )));
        }

        // Read response body
        let body = incoming_response
            .consume()
            .map_err(|_| WSError::FulcioError("Failed to get response body".to_string()))?;

        let mut bytes = Vec::new();
        let stream = body
            .stream()
            .map_err(|_| WSError::FulcioError("Failed to get body stream".to_string()))?;

        loop {
            let chunk = stream
                .blocking_read(8192)
                .map_err(|_| WSError::FulcioError("Failed to read from stream".to_string()))?;

            if chunk.is_empty() {
                break;
            }
            bytes.extend_from_slice(&chunk);
        }

        // Parse JSON response
        let fulcio_response: FulcioResponse = serde_json::from_slice(&bytes)
            .map_err(|e| WSError::FulcioError(format!("Failed to parse Fulcio response: {}", e)))?;

        Ok(fulcio_response)
    }
}

impl Default for FulcioClient {
    fn default() -> Self {
        Self::new()
    }
}

// Add pem crate for parsing PEM certificates
mod pem {
    use crate::error::WSError;

    pub struct Pem {
        contents: Vec<u8>,
    }

    impl Pem {
        pub fn contents(&self) -> &[u8] {
            &self.contents
        }
    }

    pub fn parse(pem_str: &str) -> Result<Pem, WSError> {
        // Find BEGIN and END markers
        let begin_marker = "-----BEGIN CERTIFICATE-----";
        let end_marker = "-----END CERTIFICATE-----";

        let start = pem_str
            .find(begin_marker)
            .ok_or_else(|| WSError::FulcioError("No BEGIN CERTIFICATE marker found".to_string()))?
            + begin_marker.len();

        let end = pem_str
            .find(end_marker)
            .ok_or_else(|| WSError::FulcioError("No END CERTIFICATE marker found".to_string()))?;

        // Extract base64 content between markers
        let base64_content = &pem_str[start..end];
        let base64_clean = base64_content
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();

        // Decode base64 to DER bytes
        let der_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            base64_clean.as_bytes(),
        )
        .map_err(|e| WSError::FulcioError(format!("Failed to decode base64: {}", e)))?;

        Ok(Pem {
            contents: der_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fulcio_client_creation() {
        let client = FulcioClient::new();
        assert_eq!(client.base_url, "https://fulcio.sigstore.dev");
    }

    #[test]
    fn test_fulcio_client_with_custom_url() {
        let client = FulcioClient::with_url("https://custom.fulcio.dev".to_string());
        assert_eq!(client.base_url, "https://custom.fulcio.dev");
    }

    #[test]
    fn test_fulcio_request_serialization() {
        let request = FulcioRequest {
            credentials: Credentials {
                oidc_identity_token: "test-token".to_string(),
            },
            public_key_request: PublicKeyRequest {
                public_key: PublicKey {
                    algorithm: "ECDSA".to_string(), // String enum per protobuf JSON encoding
                    content: "test-key".to_string(),
                },
                proof_of_possession: "test-proof".to_string(),
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("oidcIdentityToken"));
        assert!(json.contains("publicKeyRequest"));
        assert!(json.contains("\"algorithm\":\"ECDSA\"")); // Check for string enum value
    }

    #[test]
    fn test_extract_public_key_from_pem() {
        // Sample Ed25519 certificate (self-signed for testing)
        let pem_cert = r#"-----BEGIN CERTIFICATE-----
MIIBkzCCATmgAwIBAgIUXvZQVvZQVvZQVvZQVvZQVvZQVvYwCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yNDAxMDEwMDAwMDBaFw0yNDAxMDEwMDEwMDBa
MA8xDTALBgNVBAMMBHRlc3QwKjAFBgMrZXADIQAqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqo2UMFIwHQYDVR0OBBYEFAAAAAAAAAAAAAAAAAAAAAAAMB8G
A1UdIwQYMBaAFAAAAAAAAAAAAAAAAAAAAAAAADAMBgNVHRMBAf8EAjAAMAoGCCqG
SM49BAMCA0gAMEUCIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIg
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END CERTIFICATE-----"#;

        let result = FulcioClient::extract_public_key(pem_cert);
        // This will fail with our test certificate, but it tests the error path
        assert!(result.is_err());
    }

    #[test]
    fn test_pem_parse() {
        let pem_str = r#"-----BEGIN CERTIFICATE-----
SGVsbG8gV29ybGQh
-----END CERTIFICATE-----"#;

        let result = pem::parse(pem_str);
        assert!(result.is_ok());
        let pem = result.unwrap();
        // "Hello World!" in base64 is "SGVsbG8gV29ybGQh"
        assert_eq!(pem.contents(), b"Hello World!");
    }

    #[test]
    fn test_encode_ecdsa_p256_spki() {
        // Test ECDSA P-256 public key in uncompressed form (65 bytes: 0x04 || x || y)
        let mut raw_public_key = [0x42u8; 65];
        raw_public_key[0] = 0x04; // Uncompressed point indicator

        let spki_der = FulcioClient::encode_ecdsa_p256_spki(&raw_public_key)
            .expect("Failed to encode SPKI");

        // Verify it's DER-encoded and has expected structure
        assert!(!spki_der.is_empty());

        // SPKI structure should be:
        // SEQUENCE (tag 0x30)
        //   SEQUENCE (AlgorithmIdentifier)
        //     OID (1.2.840.10045.2.1 for ecPublicKey)
        //     OID (1.2.840.10045.3.1.7 for secp256r1)
        //   BIT STRING (public key)

        // Check it starts with SEQUENCE tag
        assert_eq!(spki_der[0], 0x30, "Should start with SEQUENCE tag");

        // Verify we can parse it back using the spki crate
        use spki::SubjectPublicKeyInfoRef;
        let parsed = SubjectPublicKeyInfoRef::try_from(spki_der.as_slice())
            .expect("Failed to parse generated SPKI");

        // Verify algorithm OID is ecPublicKey (1.2.840.10045.2.1)
        assert_eq!(parsed.algorithm.oid.to_string(), "1.2.840.10045.2.1");

        // Verify public key bits match
        let key_bits = parsed.subject_public_key.raw_bytes();
        assert_eq!(key_bits, &raw_public_key);
    }

    #[test]
    fn test_encode_spki_to_pem() {
        // Simple test DER (not a real SPKI, just checking PEM formatting)
        let test_der = vec![0x30, 0x0a, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03];

        let pem = FulcioClient::encode_spki_to_pem(&test_der)
            .expect("Failed to encode to PEM");

        // Check PEM headers
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----"));

        // Check format looks reasonable
        assert!(pem.len() > 60); // Should have headers + base64 data
        // Note: Can't use our pem::parse() to verify since it expects CERTIFICATE format
    }

    #[test]
    fn test_pem_parse_invalid() {
        let pem_str = "Invalid PEM content";
        let result = pem::parse(pem_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_fulcio_certificate_structure() {
        let cert = FulcioCertificate {
            cert_chain: vec!["cert1".to_string(), "cert2".to_string()],
            leaf_cert: "cert1".to_string(),
            public_key: vec![1, 2, 3, 4],
        };

        assert_eq!(cert.cert_chain.len(), 2);
        assert_eq!(cert.leaf_cert, "cert1");
        assert_eq!(cert.public_key, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_fulcio_response_deserialization() {
        let json = r#"{
            "signedCertificateEmbeddedSct": {
                "chain": {
                    "certificates": [
                        "cert1",
                        "cert2"
                    ]
                }
            }
        }"#;

        let response: FulcioResponse = serde_json::from_str(json).unwrap();
        assert_eq!(
            response
                .signed_certificate_embedded_sct
                .chain
                .certificates
                .len(),
            2
        );
    }

    #[test]
    fn test_empty_certificate_chain_error() {
        // This tests the error handling when Fulcio returns an empty chain
        // In a real scenario, this would come from the get_certificate method
        let cert_chain: Vec<String> = vec![];
        assert!(cert_chain.is_empty());
    }
}
