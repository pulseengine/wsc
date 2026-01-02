//! TUF-based trust bundle generation from Sigstore
//!
//! Fetches trust material from the Sigstore TUF repository and generates
//! a TrustBundle for air-gapped verification.

use crate::airgapped::{CertificateAuthority, TransparencyLog, TrustBundle, ValidityPeriod};
use crate::error::WSError;
use serde::Deserialize;

/// Default URL for Sigstore's trusted_root.json
pub const SIGSTORE_TRUSTED_ROOT_URL: &str =
    "https://raw.githubusercontent.com/sigstore/root-signing/refs/heads/main/targets/trusted_root.json";

/// Sigstore TUF trusted root structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigstoreTrustedRoot {
    /// Transparency logs (Rekor)
    #[serde(default)]
    pub tlogs: Vec<TlogEntry>,

    /// Certificate authorities (Fulcio)
    #[serde(default)]
    pub certificate_authorities: Vec<CertificateAuthorityEntry>,

    /// Certificate Transparency logs (optional)
    #[serde(default)]
    pub ctlogs: Vec<CtlogEntry>,

    /// Timestamp authorities (optional)
    #[serde(default)]
    pub timestamp_authorities: Vec<TimestampAuthorityEntry>,
}

/// Transparency log entry (Rekor)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlogEntry {
    /// Base URL of the log
    pub base_url: String,

    /// Hash algorithm used
    pub hash_algorithm: String,

    /// Public key for verification
    pub public_key: PublicKeyEntry,

    /// Log ID
    pub log_id: LogIdEntry,
}

/// Certificate authority entry (Fulcio)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateAuthorityEntry {
    /// Subject information
    pub subject: SubjectEntry,

    /// URI of the CA
    pub uri: String,

    /// Certificate chain
    pub cert_chain: CertChainEntry,

    /// Validity period
    #[serde(default)]
    pub valid_for: Option<ValidForEntry>,
}

/// Certificate chain
#[derive(Debug, Deserialize)]
pub struct CertChainEntry {
    pub certificates: Vec<CertificateEntry>,
}

/// Single certificate
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateEntry {
    /// Base64-encoded DER certificate
    pub raw_bytes: String,
}

/// Subject information
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectEntry {
    pub organization: String,
    pub common_name: String,
}

/// Public key entry
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyEntry {
    /// Base64-encoded DER public key
    pub raw_bytes: String,

    /// Key type details
    pub key_details: String,

    /// Validity period
    #[serde(default)]
    pub valid_for: Option<ValidForEntry>,
}

/// Log ID entry
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogIdEntry {
    /// Base64-encoded key ID
    pub key_id: String,
}

/// Validity period entry
#[derive(Debug, Deserialize)]
pub struct ValidForEntry {
    /// Start time (RFC 3339)
    pub start: String,

    /// End time (RFC 3339, optional)
    #[serde(default)]
    pub end: Option<String>,
}

/// CT log entry (for future use)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CtlogEntry {
    pub base_url: String,
    pub hash_algorithm: String,
    pub public_key: PublicKeyEntry,
    pub log_id: LogIdEntry,
}

/// Timestamp authority entry (for future use)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimestampAuthorityEntry {
    pub subject: SubjectEntry,
    pub uri: String,
    pub cert_chain: CertChainEntry,
    #[serde(default)]
    pub valid_for: Option<ValidForEntry>,
}

/// Fetch and parse the Sigstore trusted root
///
/// Note: In WASI targets, network access requires Wasmtime to be configured
/// with socket capabilities (e.g., `wasmtime --wasi=network=127.0.0.1`).
pub fn fetch_sigstore_trusted_root() -> Result<SigstoreTrustedRoot, WSError> {
    fetch_sigstore_trusted_root_from_url(SIGSTORE_TRUSTED_ROOT_URL)
}

/// Fetch and parse trusted root from a custom URL
pub fn fetch_sigstore_trusted_root_from_url(url: &str) -> Result<SigstoreTrustedRoot, WSError> {
    let response = ureq::get(url)
        .call()
        .map_err(|e| WSError::InternalError(format!("Failed to fetch trusted root: {}", e)))?;

    let body = response
        .into_body()
        .read_to_string()
        .map_err(|e| WSError::InternalError(format!("Failed to read response: {}", e)))?;

    parse_trusted_root(&body)
}

/// Parse trusted root from JSON string
pub fn parse_trusted_root(json: &str) -> Result<SigstoreTrustedRoot, WSError> {
    serde_json::from_str(json)
        .map_err(|e| WSError::InternalError(format!("Failed to parse trusted root: {}", e)))
}

/// Convert Sigstore trusted root to wsc TrustBundle
pub fn trusted_root_to_bundle(
    root: &SigstoreTrustedRoot,
    bundle_version: u32,
    validity_days: u32,
) -> Result<TrustBundle, WSError> {
    let mut bundle = TrustBundle::new(bundle_version, validity_days);

    // Convert certificate authorities
    for ca_entry in &root.certificate_authorities {
        let ca = convert_certificate_authority(ca_entry)?;
        bundle.add_certificate_authority(ca);
    }

    // Convert transparency logs
    for tlog_entry in &root.tlogs {
        let log = convert_transparency_log(tlog_entry)?;
        bundle.add_transparency_log(log);
    }

    // Compute bundle ID
    bundle.compute_bundle_id()?;

    Ok(bundle)
}

/// Convert a Sigstore CA entry to wsc CertificateAuthority
fn convert_certificate_authority(entry: &CertificateAuthorityEntry) -> Result<CertificateAuthority, WSError> {
    let mut pem_certs = Vec::new();

    for cert in &entry.cert_chain.certificates {
        let pem = der_to_pem(&cert.raw_bytes, "CERTIFICATE")?;
        pem_certs.push(pem);
    }

    let (not_before, not_after) = if let Some(valid_for) = &entry.valid_for {
        (
            parse_rfc3339(&valid_for.start)?,
            valid_for
                .end
                .as_ref()
                .map(|e| parse_rfc3339(e))
                .transpose()?
                .unwrap_or_else(|| {
                    // No end date means valid indefinitely - use 10 years from now
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        + (10 * 365 * 86400)
                }),
        )
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        (now, now + (10 * 365 * 86400))
    };

    Ok(CertificateAuthority {
        name: format!("{} - {}", entry.subject.organization, entry.subject.common_name),
        uri: entry.uri.clone(),
        certificates_pem: pem_certs,
        valid_for: ValidityPeriod {
            not_before,
            not_after,
            grace_period_seconds: 0,
        },
    })
}

/// Convert a Sigstore tlog entry to wsc TransparencyLog
fn convert_transparency_log(entry: &TlogEntry) -> Result<TransparencyLog, WSError> {
    let pem = der_to_pem(&entry.public_key.raw_bytes, "PUBLIC KEY")?;

    let (not_before, not_after) = if let Some(valid_for) = &entry.public_key.valid_for {
        (
            parse_rfc3339(&valid_for.start)?,
            valid_for
                .end
                .as_ref()
                .map(|e| parse_rfc3339(e))
                .transpose()?
                .unwrap_or_else(|| {
                    // No end date - use 10 years from now
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        + (10 * 365 * 86400)
                }),
        )
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        (now, now + (10 * 365 * 86400))
    };

    // Decode log ID from base64
    let log_id_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &entry.log_id.key_id,
    )
    .map_err(|e| WSError::InternalError(format!("Invalid log ID base64: {}", e)))?;

    Ok(TransparencyLog {
        base_url: entry.base_url.clone(),
        hash_algorithm: entry.hash_algorithm.to_lowercase().replace("_", "-"),
        public_key_pem: pem,
        log_id: hex::encode(&log_id_bytes),
        valid_for: ValidityPeriod {
            not_before,
            not_after,
            grace_period_seconds: 0,
        },
    })
}

/// Convert base64-encoded DER to PEM format
fn der_to_pem(base64_der: &str, label: &str) -> Result<String, WSError> {
    // Validate base64 by decoding
    let _ = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        base64_der,
    )
    .map_err(|e| WSError::InternalError(format!("Invalid base64: {}", e)))?;

    // Format as PEM (wrap at 64 characters)
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for (i, c) in base64_der.chars().enumerate() {
        pem.push(c);
        if (i + 1) % 64 == 0 {
            pem.push('\n');
        }
    }
    if !pem.ends_with('\n') {
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));

    Ok(pem)
}

/// Parse RFC 3339 timestamp to Unix timestamp
fn parse_rfc3339(s: &str) -> Result<u64, WSError> {
    // Simple RFC 3339 parser for common formats
    // Format: YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DDTHH:MM:SS.sssZ

    let s = s.trim_end_matches('Z');
    let s = s.split('.').next().unwrap_or(s); // Remove fractional seconds

    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 {
        return Err(WSError::InternalError(format!("Invalid RFC 3339: {}", s)));
    }

    let date_parts: Vec<u32> = parts[0]
        .split('-')
        .filter_map(|p| p.parse().ok())
        .collect();
    let time_parts: Vec<u32> = parts[1]
        .split(':')
        .filter_map(|p| p.parse().ok())
        .collect();

    if date_parts.len() != 3 || time_parts.len() != 3 {
        return Err(WSError::InternalError(format!("Invalid RFC 3339: {}", s)));
    }

    let (year, month, day) = (date_parts[0], date_parts[1], date_parts[2]);
    let (hour, min, sec) = (time_parts[0], time_parts[1], time_parts[2]);

    // Calculate days since Unix epoch (simplified, ignores leap seconds)
    let mut days: i64 = 0;

    // Years
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Months
    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += days_in_month[(m - 1) as usize] as i64;
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }

    // Days
    days += (day - 1) as i64;

    // Calculate seconds
    let seconds = days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64);

    Ok(seconds as u64)
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TRUSTED_ROOT: &str = r#"{
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [
            {
                "baseUrl": "https://rekor.sigstore.dev",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==",
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                    "validFor": {
                        "start": "2021-01-12T11:53:27Z"
                    }
                },
                "logId": {
                    "keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
                }
            }
        ],
        "certificateAuthorities": [
            {
                "subject": {
                    "organization": "sigstore.dev",
                    "commonName": "sigstore"
                },
                "uri": "https://fulcio.sigstore.dev",
                "certChain": {
                    "certificates": [
                        {
                            "rawBytes": "MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ"
                        }
                    ]
                },
                "validFor": {
                    "start": "2021-10-07T13:56:59Z"
                }
            }
        ]
    }"#;

    #[test]
    fn test_parse_trusted_root() {
        let root = parse_trusted_root(SAMPLE_TRUSTED_ROOT).unwrap();
        assert_eq!(root.tlogs.len(), 1);
        assert_eq!(root.certificate_authorities.len(), 1);
        assert_eq!(root.tlogs[0].base_url, "https://rekor.sigstore.dev");
    }

    #[test]
    fn test_trusted_root_to_bundle() {
        let root = parse_trusted_root(SAMPLE_TRUSTED_ROOT).unwrap();
        let bundle = trusted_root_to_bundle(&root, 1, 365).unwrap();

        assert_eq!(bundle.version, 1);
        assert_eq!(bundle.transparency_logs.len(), 1);
        assert_eq!(bundle.certificate_authorities.len(), 1);
        assert!(bundle.transparency_logs[0].public_key_pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(bundle.certificate_authorities[0].certificates_pem[0].contains("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn test_der_to_pem() {
        let der_b64 = "SGVsbG8gV29ybGQ="; // "Hello World"
        let pem = der_to_pem(der_b64, "TEST").unwrap();
        assert!(pem.starts_with("-----BEGIN TEST-----\n"));
        assert!(pem.ends_with("-----END TEST-----\n"));
        assert!(pem.contains("SGVsbG8gV29ybGQ="));
    }

    #[test]
    fn test_parse_rfc3339() {
        // 2021-01-12T11:53:27Z
        let ts = parse_rfc3339("2021-01-12T11:53:27Z").unwrap();
        // Approximate check (should be around 1610452407)
        assert!(ts > 1600000000 && ts < 1700000000);

        // With fractional seconds
        let ts2 = parse_rfc3339("2022-10-31T23:59:59.999Z").unwrap();
        assert!(ts2 > ts);
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000)); // Divisible by 400
        assert!(!is_leap_year(1900)); // Divisible by 100 but not 400
        assert!(is_leap_year(2024)); // Divisible by 4
        assert!(!is_leap_year(2023)); // Not divisible by 4
    }
}
