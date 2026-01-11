//! Supply chain verification policy engine.
//!
//! This module provides a policy engine for enforcing SLSA levels and
//! supply chain security policies on WebAssembly transformation chains.
//!
//! # Policy File Format (TOML)
//!
//! ```toml
//! [policy]
//! name = "production-strict"
//! version = "1.0"
//! enforcement = "strict"  # or "report"
//!
//! [slsa]
//! minimum_level = 2  # L0-L4
//! enforcement = "strict"
//!
//! [signatures]
//! require_root_signatures = true
//! require_attestation_signatures = true
//! max_attestation_age_days = 30
//!
//! [trusted_tools.loom]
//! min_version = "0.1.0"
//! public_keys = [{ algorithm = "ed25519", key = "...", key_id = "loom-prod" }]
//!
//! [trusted_builders.github-actions]
//! builder_id = "https://github.com/actions/runner"
//! oidc_issuer = "https://token.actions.githubusercontent.com"
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use wsc::policy::{Policy, evaluate_policy};
//! use wsc::composition::TransformationAttestation;
//!
//! let policy = Policy::from_toml_file("wsc-policy.toml")?;
//! let result = evaluate_policy(&attestation, &policy);
//!
//! if result.passed {
//!     println!("SLSA Level: {:?}", result.slsa_level);
//! } else {
//!     for rule in result.rules.iter().filter(|r| !r.passed) {
//!         eprintln!("FAILED: {} - {}", rule.rule, rule.message);
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

pub mod slsa;
pub mod eval;

pub use slsa::{SlsaLevel, detect_slsa_level};
pub use eval::{evaluate_policy, PolicyEvaluationResult, RuleResult, PolicySummary};

// ============================================================================
// Core Policy Types
// ============================================================================

/// Enforcement mode for policy rules.
///
/// Determines whether a rule violation causes verification to fail
/// or is just reported as a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Enforcement {
    /// Violation causes verification to fail
    #[default]
    Strict,
    /// Violation is reported but doesn't fail verification
    Report,
}

impl std::fmt::Display for Enforcement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Enforcement::Strict => write!(f, "strict"),
            Enforcement::Report => write!(f, "report"),
        }
    }
}

/// A supply chain verification policy.
///
/// Policies define requirements for SLSA levels, signatures, trusted tools,
/// and trusted builders. Each section can have its own enforcement mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy metadata
    #[serde(default)]
    pub policy: PolicyMetadata,

    /// SLSA level requirements
    #[serde(default)]
    pub slsa: SlsaPolicy,

    /// Signature requirements
    #[serde(default)]
    pub signatures: SignaturePolicy,

    /// Trusted transformation tools
    #[serde(default)]
    pub trusted_tools: HashMap<String, TrustedToolPolicy>,

    /// Trusted CI/CD builders for SLSA provenance
    #[serde(default)]
    pub trusted_builders: HashMap<String, TrustedBuilderPolicy>,
}

/// Policy metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    /// Human-readable policy name
    #[serde(default = "default_policy_name")]
    pub name: String,

    /// Policy version
    #[serde(default = "default_policy_version")]
    pub version: String,

    /// Default enforcement mode for all rules
    #[serde(default)]
    pub enforcement: Enforcement,
}

fn default_policy_name() -> String {
    "default".to_string()
}

fn default_policy_version() -> String {
    "1.0".to_string()
}

impl Default for PolicyMetadata {
    fn default() -> Self {
        Self {
            name: default_policy_name(),
            version: default_policy_version(),
            enforcement: Enforcement::default(),
        }
    }
}

/// SLSA-specific policy requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaPolicy {
    /// Minimum required SLSA level (0-4)
    #[serde(default)]
    pub minimum_level: u8,

    /// Enforcement mode for SLSA checks
    #[serde(default)]
    pub enforcement: Option<Enforcement>,
}

impl Default for SlsaPolicy {
    fn default() -> Self {
        Self {
            minimum_level: 0,
            enforcement: None,
        }
    }
}

/// Signature requirements policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePolicy {
    /// Require root components to be signed
    #[serde(default)]
    pub require_root_signatures: bool,

    /// Require transformation attestations to be signed
    #[serde(default)]
    pub require_attestation_signatures: bool,

    /// Maximum age for attestations in days
    #[serde(default)]
    pub max_attestation_age_days: Option<u64>,

    /// Enforcement mode for signature checks
    #[serde(default)]
    pub enforcement: Option<Enforcement>,
}

impl Default for SignaturePolicy {
    fn default() -> Self {
        Self {
            require_root_signatures: false,
            require_attestation_signatures: false,
            max_attestation_age_days: None,
            enforcement: None,
        }
    }
}

impl SignaturePolicy {
    /// Get max attestation age as Duration
    pub fn max_attestation_age(&self) -> Option<Duration> {
        self.max_attestation_age_days
            .map(|days| Duration::from_secs(days * 24 * 60 * 60))
    }
}

/// Trusted transformation tool configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedToolPolicy {
    /// Minimum required version (semver)
    #[serde(default)]
    pub min_version: Option<String>,

    /// Maximum allowed version (semver)
    #[serde(default)]
    pub max_version: Option<String>,

    /// Required tool binary hash
    #[serde(default)]
    pub required_hash: Option<String>,

    /// Trusted public keys for signature verification
    #[serde(default)]
    pub public_keys: Vec<TrustedPublicKeyConfig>,

    /// Keyless (OIDC) verification configuration
    #[serde(default)]
    pub keyless: Option<KeylessConfig>,

    /// Enforcement mode for this tool
    #[serde(default)]
    pub enforcement: Option<Enforcement>,
}

impl Default for TrustedToolPolicy {
    fn default() -> Self {
        Self {
            min_version: None,
            max_version: None,
            required_hash: None,
            public_keys: Vec::new(),
            keyless: None,
            enforcement: None,
        }
    }
}

/// Public key configuration for trusted tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPublicKeyConfig {
    /// Signing algorithm (e.g., "ed25519", "ecdsa-p256")
    pub algorithm: String,

    /// Base64-encoded public key
    pub key: String,

    /// Optional key identifier
    #[serde(default)]
    pub key_id: Option<String>,
}

/// Keyless (OIDC) verification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeylessConfig {
    /// Trusted OIDC token issuers
    #[serde(default)]
    pub oidc_issuers: Vec<String>,

    /// Allowed certificate subjects (supports wildcards)
    #[serde(default)]
    pub subjects: Vec<String>,
}

/// Trusted CI/CD builder configuration for SLSA provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedBuilderPolicy {
    /// Builder identity URI
    pub builder_id: String,

    /// Expected OIDC issuer
    #[serde(default)]
    pub oidc_issuer: Option<String>,

    /// Allowed repository patterns (supports wildcards)
    #[serde(default)]
    pub allowed_repos: Vec<String>,

    /// Enforcement mode for this builder
    #[serde(default)]
    pub enforcement: Option<Enforcement>,
}

// ============================================================================
// Policy Loading
// ============================================================================

/// Error type for policy operations.
#[derive(Debug, Clone)]
pub enum PolicyError {
    /// Failed to parse TOML
    ParseError(String),
    /// Failed to read file
    IoError(String),
    /// Invalid policy configuration
    ValidationError(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::ParseError(msg) => write!(f, "Policy parse error: {}", msg),
            PolicyError::IoError(msg) => write!(f, "Policy I/O error: {}", msg),
            PolicyError::ValidationError(msg) => write!(f, "Policy validation error: {}", msg),
        }
    }
}

impl std::error::Error for PolicyError {}

impl Policy {
    /// Create a default permissive policy (no requirements).
    pub fn permissive() -> Self {
        Self {
            policy: PolicyMetadata {
                name: "permissive".to_string(),
                version: "1.0".to_string(),
                enforcement: Enforcement::Report,
            },
            slsa: SlsaPolicy::default(),
            signatures: SignaturePolicy::default(),
            trusted_tools: HashMap::new(),
            trusted_builders: HashMap::new(),
        }
    }

    /// Create a strict policy requiring SLSA L2 and signed attestations.
    pub fn strict() -> Self {
        Self {
            policy: PolicyMetadata {
                name: "strict".to_string(),
                version: "1.0".to_string(),
                enforcement: Enforcement::Strict,
            },
            slsa: SlsaPolicy {
                minimum_level: 2,
                enforcement: Some(Enforcement::Strict),
            },
            signatures: SignaturePolicy {
                require_root_signatures: true,
                require_attestation_signatures: true,
                max_attestation_age_days: Some(30),
                enforcement: Some(Enforcement::Strict),
            },
            trusted_tools: HashMap::new(),
            trusted_builders: HashMap::new(),
        }
    }

    /// Parse policy from TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, PolicyError> {
        toml::from_str(toml_str).map_err(|e| PolicyError::ParseError(e.to_string()))
    }

    /// Load policy from TOML file.
    pub fn from_toml_file(path: &str) -> Result<Self, PolicyError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| PolicyError::IoError(format!("{}: {}", path, e)))?;
        Self::from_toml(&content)
    }

    /// Serialize policy to TOML string.
    pub fn to_toml(&self) -> Result<String, PolicyError> {
        toml::to_string_pretty(self).map_err(|e| PolicyError::ParseError(e.to_string()))
    }

    /// Get effective enforcement for a section.
    pub fn effective_enforcement(&self, section_enforcement: Option<Enforcement>) -> Enforcement {
        section_enforcement.unwrap_or(self.policy.enforcement)
    }

    /// Add a trusted tool to the policy.
    pub fn add_trusted_tool(&mut self, name: impl Into<String>, tool: TrustedToolPolicy) {
        self.trusted_tools.insert(name.into(), tool);
    }

    /// Add a trusted builder to the policy.
    pub fn add_trusted_builder(&mut self, name: impl Into<String>, builder: TrustedBuilderPolicy) {
        self.trusted_builders.insert(name.into(), builder);
    }

    /// Check if a tool is trusted.
    pub fn is_tool_trusted(&self, name: &str) -> bool {
        self.trusted_tools.contains_key(name)
    }

    /// Get trusted tool configuration.
    pub fn get_trusted_tool(&self, name: &str) -> Option<&TrustedToolPolicy> {
        self.trusted_tools.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_policy() {
        let toml = r#"
[policy]
name = "test"
"#;
        let policy = Policy::from_toml(toml).unwrap();
        assert_eq!(policy.policy.name, "test");
        assert_eq!(policy.slsa.minimum_level, 0);
    }

    #[test]
    fn test_parse_full_policy() {
        let toml = r#"
[policy]
name = "production"
version = "1.0"
enforcement = "strict"

[slsa]
minimum_level = 2
enforcement = "strict"

[signatures]
require_root_signatures = true
require_attestation_signatures = true
max_attestation_age_days = 30

[trusted_tools.loom]
min_version = "0.1.0"
public_keys = [{ algorithm = "ed25519", key = "abc123", key_id = "loom-prod" }]

[trusted_tools.wac]
min_version = "0.5.0"
keyless = { oidc_issuers = ["https://token.actions.githubusercontent.com"], subjects = ["https://github.com/bytecodealliance/*"] }

[trusted_builders.github-actions]
builder_id = "https://github.com/actions/runner"
oidc_issuer = "https://token.actions.githubusercontent.com"
allowed_repos = ["pulseengine/*"]
"#;
        let policy = Policy::from_toml(toml).unwrap();

        assert_eq!(policy.policy.name, "production");
        assert_eq!(policy.policy.enforcement, Enforcement::Strict);
        assert_eq!(policy.slsa.minimum_level, 2);
        assert!(policy.signatures.require_root_signatures);
        assert!(policy.signatures.require_attestation_signatures);
        assert_eq!(policy.signatures.max_attestation_age_days, Some(30));

        assert!(policy.trusted_tools.contains_key("loom"));
        assert!(policy.trusted_tools.contains_key("wac"));

        let loom = policy.trusted_tools.get("loom").unwrap();
        assert_eq!(loom.min_version, Some("0.1.0".to_string()));
        assert_eq!(loom.public_keys.len(), 1);

        let wac = policy.trusted_tools.get("wac").unwrap();
        assert!(wac.keyless.is_some());

        assert!(policy.trusted_builders.contains_key("github-actions"));
    }

    #[test]
    fn test_enforcement_default() {
        let policy = Policy::permissive();
        assert_eq!(policy.policy.enforcement, Enforcement::Report);

        let policy = Policy::strict();
        assert_eq!(policy.policy.enforcement, Enforcement::Strict);
    }

    #[test]
    fn test_effective_enforcement() {
        let mut policy = Policy::permissive();
        policy.policy.enforcement = Enforcement::Report;

        // Section without override uses default
        assert_eq!(
            policy.effective_enforcement(None),
            Enforcement::Report
        );

        // Section with override uses override
        assert_eq!(
            policy.effective_enforcement(Some(Enforcement::Strict)),
            Enforcement::Strict
        );
    }

    #[test]
    fn test_policy_to_toml() {
        let policy = Policy::strict();
        let toml = policy.to_toml().unwrap();

        assert!(toml.contains("[policy]"));
        assert!(toml.contains("strict"));

        // Round-trip
        let parsed = Policy::from_toml(&toml).unwrap();
        assert_eq!(parsed.policy.name, policy.policy.name);
    }

    #[test]
    fn test_max_attestation_age() {
        let mut policy = SignaturePolicy::default();
        assert!(policy.max_attestation_age().is_none());

        policy.max_attestation_age_days = Some(30);
        let duration = policy.max_attestation_age().unwrap();
        assert_eq!(duration, Duration::from_secs(30 * 24 * 60 * 60));
    }
}
