/// Keyless signing support for wasmsign2
///
/// This module implements keyless (ephemeral key) signing using:
/// - OIDC identity tokens (GitHub Actions, Google Cloud, GitLab CI)
/// - Fulcio for short-lived certificates
/// - Rekor for transparency log entries

mod format;
pub mod oidc;
pub mod fulcio;
pub mod rekor;
pub mod signer;
pub mod cert_verifier;

pub use format::*;
pub use oidc::{
    detect_oidc_provider, GitHubOidcProvider, GitLabOidcProvider, GoogleOidcProvider, OidcProvider,
    OidcToken,
};
pub use fulcio::{FulcioClient, FulcioCertificate};
pub use rekor::{RekorClient, RekorEntry};
pub use signer::{KeylessConfig, KeylessSigner, KeylessVerifier};
pub use cert_verifier::{CertificatePool, CertVerificationError};
