//! Audit logging for WSC signing and verification operations.
//!
//! This module provides structured audit logging for security-sensitive operations,
//! designed for compliance with ISO/SAE 21434, IEC 62443, and SOC 2 requirements.
//!
//! # Usage
//!
//! ```rust,ignore
//! use wsc::audit::{self, AuditConfig, LogDestination};
//!
//! // Initialize audit logging (typically once at program start)
//! audit::init(AuditConfig {
//!     enabled: true,
//!     destination: LogDestination::Stdout,
//!     json_format: true,
//!     redact_pii: true,
//! });
//!
//! // Audit events are automatically logged during signing/verification
//! ```
//!
//! # Event Types
//!
//! - `signing.attempt` - Signing operation started
//! - `signing.success` - Signing completed successfully
//! - `signing.failure` - Signing failed
//! - `verification.attempt` - Verification started
//! - `verification.success` - Verification passed
//! - `verification.failure` - Verification failed
//!
//! # JSON Output Example
//!
//! ```json
//! {
//!   "timestamp": "2026-01-04T20:00:00Z",
//!   "level": "INFO",
//!   "target": "wsc::audit",
//!   "event_type": "signing.success",
//!   "identity": "us***@example.com",
//!   "artifact_hash": "sha256:e3b0c442...",
//!   "rekor_uuid": "24296fb24b8ad77a..."
//! }
//! ```

use std::sync::OnceLock;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    prelude::*,
    EnvFilter,
};

/// Global audit configuration state
static AUDIT_INITIALIZED: OnceLock<bool> = OnceLock::new();

/// Audit log configuration
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Enable audit logging (default: true)
    pub enabled: bool,
    /// Log destination
    pub destination: LogDestination,
    /// Use JSON format (default: true for production)
    pub json_format: bool,
    /// Redact PII like email addresses (default: true)
    pub redact_pii: bool,
    /// Log level filter (default: "wsc::audit=info")
    pub filter: String,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            destination: LogDestination::Stderr,
            json_format: true,
            redact_pii: true,
            filter: "wsc::audit=info".to_string(),
        }
    }
}

/// Audit log destination
#[derive(Debug, Clone, Default)]
pub enum LogDestination {
    /// Write to stdout
    Stdout,
    /// Write to stderr (default)
    #[default]
    Stderr,
    /// Write to a file (path)
    File(String),
}

/// Initialize the audit logging subsystem.
///
/// This should be called once at program startup. Subsequent calls are ignored.
///
/// # Example
///
/// ```rust,ignore
/// wsc::audit::init(AuditConfig::default());
/// ```
pub fn init(config: AuditConfig) {
    // Only initialize once
    if AUDIT_INITIALIZED.get().is_some() {
        return;
    }

    if !config.enabled {
        let _ = AUDIT_INITIALIZED.set(true);
        return;
    }

    let filter = EnvFilter::try_new(&config.filter).unwrap_or_else(|_| EnvFilter::new("info"));

    match config.destination {
        LogDestination::Stdout => {
            if config.json_format {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(
                        fmt::layer()
                            .json()
                            .with_target(true)
                            .with_span_events(FmtSpan::NONE)
                            .with_writer(std::io::stdout),
                    )
                    .init();
            } else {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer().with_target(true).with_writer(std::io::stdout))
                    .init();
            }
        }
        LogDestination::Stderr => {
            if config.json_format {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(
                        fmt::layer()
                            .json()
                            .with_target(true)
                            .with_span_events(FmtSpan::NONE)
                            .with_writer(std::io::stderr),
                    )
                    .init();
            } else {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer().with_target(true).with_writer(std::io::stderr))
                    .init();
            }
        }
        LogDestination::File(path) => {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .expect("Failed to open audit log file");

            if config.json_format {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(
                        fmt::layer()
                            .json()
                            .with_target(true)
                            .with_span_events(FmtSpan::NONE)
                            .with_writer(std::sync::Mutex::new(file)),
                    )
                    .init();
            } else {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(
                        fmt::layer()
                            .with_target(true)
                            .with_writer(std::sync::Mutex::new(file)),
                    )
                    .init();
            }
        }
    }

    let _ = AUDIT_INITIALIZED.set(true);
}

/// Redact an email address for PII protection.
///
/// Transforms "user@example.com" into "us***@example.com"
pub fn redact_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let local = &email[..at_pos];
        let domain = &email[at_pos..];
        let visible = std::cmp::min(2, local.len());
        format!("{}***{}", &local[..visible], domain)
    } else {
        "***".to_string()
    }
}

/// Generate a new correlation ID for tracking related audit events.
pub fn new_correlation_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ============================================================================
// Audit Event Functions
// ============================================================================

/// Log a signing attempt event.
pub fn log_signing_attempt(correlation_id: &str, artifact_hash: &str, identity: Option<&str>) {
    let identity_display = identity
        .map(|i| redact_email(i))
        .unwrap_or_else(|| "unknown".to_string());

    tracing::info!(
        target: "wsc::audit",
        event_type = "signing.attempt",
        correlation_id = correlation_id,
        artifact_hash = artifact_hash,
        identity = %identity_display,
        "Signing operation initiated"
    );
}

/// Log a successful signing event.
pub fn log_signing_success(
    correlation_id: &str,
    artifact_hash: &str,
    identity: Option<&str>,
    rekor_uuid: Option<&str>,
    certificate_fingerprint: Option<&str>,
) {
    let identity_display = identity
        .map(|i| redact_email(i))
        .unwrap_or_else(|| "unknown".to_string());

    tracing::info!(
        target: "wsc::audit",
        event_type = "signing.success",
        correlation_id = correlation_id,
        artifact_hash = artifact_hash,
        identity = %identity_display,
        rekor_uuid = rekor_uuid.unwrap_or("n/a"),
        certificate_fingerprint = certificate_fingerprint.unwrap_or("n/a"),
        "Signing operation completed successfully"
    );
}

/// Log a failed signing event.
pub fn log_signing_failure(
    correlation_id: &str,
    artifact_hash: &str,
    identity: Option<&str>,
    error_type: &str,
    error_message: &str,
) {
    let identity_display = identity
        .map(|i| redact_email(i))
        .unwrap_or_else(|| "unknown".to_string());

    // Sanitize error message to avoid leaking secrets
    let safe_message = sanitize_error_message(error_message);

    tracing::warn!(
        target: "wsc::audit",
        event_type = "signing.failure",
        correlation_id = correlation_id,
        artifact_hash = artifact_hash,
        identity = %identity_display,
        error_type = error_type,
        error_message = %safe_message,
        "Signing operation failed"
    );
}

/// Log a verification attempt event.
pub fn log_verification_attempt(correlation_id: &str, artifact_hash: &str) {
    tracing::info!(
        target: "wsc::audit",
        event_type = "verification.attempt",
        correlation_id = correlation_id,
        artifact_hash = artifact_hash,
        "Verification operation initiated"
    );
}

/// Log a successful verification event.
pub fn log_verification_success(
    correlation_id: &str,
    artifact_hash: &str,
    signer_identity: Option<&str>,
    signature_count: usize,
) {
    let identity_display = signer_identity
        .map(|i| redact_email(i))
        .unwrap_or_else(|| "unknown".to_string());

    tracing::info!(
        target: "wsc::audit",
        event_type = "verification.success",
        correlation_id = correlation_id,
        artifact_hash = artifact_hash,
        signer_identity = %identity_display,
        signature_count = signature_count,
        "Verification operation completed successfully"
    );
}

/// Log a failed verification event.
pub fn log_verification_failure(
    correlation_id: &str,
    artifact_hash: &str,
    error_type: &str,
    error_message: &str,
) {
    let safe_message = sanitize_error_message(error_message);

    tracing::warn!(
        target: "wsc::audit",
        event_type = "verification.failure",
        correlation_id = correlation_id,
        artifact_hash = artifact_hash,
        error_type = error_type,
        error_message = %safe_message,
        "Verification operation failed"
    );
}

/// Log a key generation event.
pub fn log_key_generation(correlation_id: &str, key_type: &str, key_id: Option<&str>) {
    tracing::info!(
        target: "wsc::audit",
        event_type = "key.generated",
        correlation_id = correlation_id,
        key_type = key_type,
        key_id = key_id.unwrap_or("n/a"),
        "Cryptographic key generated"
    );
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Sanitize error messages to avoid leaking sensitive information.
fn sanitize_error_message(message: &str) -> String {
    // Remove potential secrets from error messages
    let sanitized = message
        // Remove anything that looks like a token
        .split_whitespace()
        .map(|word| {
            if word.len() > 40 && word.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
            {
                "[REDACTED]"
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    // Truncate very long messages
    if sanitized.len() > 500 {
        format!("{}...", &sanitized[..497])
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_email() {
        assert_eq!(redact_email("user@example.com"), "us***@example.com");
        assert_eq!(redact_email("ab@test.org"), "ab***@test.org");
        assert_eq!(redact_email("a@x.com"), "a***@x.com");
        assert_eq!(redact_email("invalid"), "***");
    }

    #[test]
    fn test_sanitize_error_message() {
        assert_eq!(
            sanitize_error_message("Connection failed"),
            "Connection failed"
        );

        // Long token-like strings should be redacted
        let with_token = "Failed with token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        assert!(sanitize_error_message(with_token).contains("[REDACTED]"));
    }

    #[test]
    fn test_correlation_id_format() {
        let id = new_correlation_id();
        // UUID v4 format: 8-4-4-4-12
        assert_eq!(id.len(), 36);
        assert!(id.chars().filter(|c| *c == '-').count() == 4);
    }
}
