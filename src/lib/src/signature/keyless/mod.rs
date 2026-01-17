/// Certificate pinning for Sigstore endpoints (Issue #12)
///
/// Provides defense-in-depth against CA compromise and MITM attacks.
pub mod cert_pinning;
pub mod cert_verifier;
/// Rate limiting for Sigstore API endpoints (Issue #6)
pub mod rate_limit;
/// Keyless signing support for wsc
///
/// This module implements keyless (ephemeral key) signing using:
/// - OIDC identity tokens (GitHub Actions, Google Cloud, GitLab CI)
/// - Fulcio for short-lived certificates
/// - Rekor for transparency log entries
mod format;
pub mod fulcio;
pub mod merkle;
pub mod oidc;
pub mod rekor;
pub mod rekor_verifier;
pub mod signer;
/// Custom TLS transport with certificate pinning (Issue #12)
pub mod transport;

// Certificate pinning types (Issue #12)
pub use cert_pinning::{PinningConfig, PinnedCertVerifier, check_pinning_enforcement};
pub use cert_verifier::{CertVerificationError, CertificatePool};
pub use format::*;
pub use fulcio::{FulcioCertificate, FulcioClient};
pub use oidc::{
    GitHubOidcProvider, GitLabOidcProvider, GoogleOidcProvider, OidcProvider, OidcToken,
    detect_oidc_provider,
};
pub use rekor::{RekorClient, RekorEntry};
pub use rekor_verifier::RekorKeyring;
pub use signer::{KeylessConfig, KeylessSigner, KeylessVerifier, KeylessVerificationResult};
