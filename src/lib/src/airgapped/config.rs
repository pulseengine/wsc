//! Configuration for air-gapped verification

use std::time::Duration;

/// Configuration for air-gapped verification
#[derive(Debug, Clone)]
pub struct AirGappedConfig {
    /// Maximum signature age in seconds
    ///
    /// Signatures older than this are rejected even if otherwise valid.
    /// `None` means no maximum age (trust bundle validity is the limit).
    pub max_signature_age: Option<Duration>,

    /// Whether to check the revocation list
    pub check_revocations: bool,

    /// Maximum certificate chain depth
    pub max_chain_depth: u8,

    /// Required identity patterns (optional)
    pub identity_requirements: Option<IdentityRequirements>,

    /// How to handle expired trust bundles
    pub grace_period_behavior: GracePeriodBehavior,

    /// Whether to enforce anti-rollback protection
    ///
    /// When true, bundle version must be >= stored device state version.
    /// Requires persistent storage for device state.
    pub enforce_rollback_protection: bool,
}

impl Default for AirGappedConfig {
    fn default() -> Self {
        Self {
            max_signature_age: None,
            check_revocations: true,
            max_chain_depth: 4,
            identity_requirements: None,
            grace_period_behavior: GracePeriodBehavior::WarnDuringGrace,
            enforce_rollback_protection: false,
        }
    }
}

impl AirGappedConfig {
    /// Create config for fully air-gapped devices (no time source)
    pub fn fully_airgapped() -> Self {
        Self {
            max_signature_age: None,
            check_revocations: true,
            max_chain_depth: 4,
            identity_requirements: None,
            grace_period_behavior: GracePeriodBehavior::WarnOnly,
            enforce_rollback_protection: false,
        }
    }

    /// Create config for intermittently connected devices
    pub fn intermittent() -> Self {
        Self {
            max_signature_age: Some(Duration::from_secs(90 * 24 * 3600)), // 90 days
            check_revocations: true,
            max_chain_depth: 4,
            identity_requirements: None,
            grace_period_behavior: GracePeriodBehavior::WarnDuringGrace,
            enforce_rollback_protection: true,
        }
    }

    /// Create config for high-security environments
    pub fn high_security() -> Self {
        Self {
            max_signature_age: Some(Duration::from_secs(7 * 24 * 3600)), // 7 days
            check_revocations: true,
            max_chain_depth: 2,
            identity_requirements: None,
            grace_period_behavior: GracePeriodBehavior::Strict,
            enforce_rollback_protection: true,
        }
    }

    /// Set maximum signature age
    pub fn with_max_age(mut self, age: Duration) -> Self {
        self.max_signature_age = Some(age);
        self
    }

    /// Set identity requirements
    pub fn with_identity_requirements(mut self, requirements: IdentityRequirements) -> Self {
        self.identity_requirements = Some(requirements);
        self
    }

    /// Enable rollback protection
    pub fn with_rollback_protection(mut self) -> Self {
        self.enforce_rollback_protection = true;
        self
    }
}

/// Required identity patterns
#[derive(Debug, Clone)]
pub struct IdentityRequirements {
    /// Allowed OIDC issuers (exact match or glob patterns)
    ///
    /// Example: `["https://token.actions.githubusercontent.com"]`
    pub allowed_issuers: Vec<String>,

    /// Allowed subjects (exact match or glob patterns)
    ///
    /// Example: `["https://github.com/myorg/*"]`
    pub allowed_subjects: Vec<String>,
}

impl IdentityRequirements {
    /// Create requirements for GitHub Actions
    pub fn github_actions(org: &str) -> Self {
        Self {
            allowed_issuers: vec!["https://token.actions.githubusercontent.com".to_string()],
            allowed_subjects: vec![format!("https://github.com/{}/*", org)],
        }
    }

    /// Check if an issuer matches the requirements
    pub fn matches_issuer(&self, issuer: &str) -> bool {
        self.allowed_issuers.iter().any(|pattern| {
            if pattern.contains('*') {
                glob_match(pattern, issuer)
            } else {
                pattern == issuer
            }
        })
    }

    /// Check if a subject matches the requirements
    pub fn matches_subject(&self, subject: &str) -> bool {
        self.allowed_subjects.iter().any(|pattern| {
            if pattern.contains('*') {
                glob_match(pattern, subject)
            } else {
                pattern == subject
            }
        })
    }
}

/// Simple glob matching (* matches any characters)
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.is_empty() {
        return pattern == text;
    }

    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if let Some(found) = text[pos..].find(part) {
            if i == 0 && found != 0 {
                // First part must match at start
                return false;
            }
            pos += found + part.len();
        } else {
            return false;
        }
    }

    // If pattern doesn't end with *, text must end at pos
    if !pattern.ends_with('*') && pos != text.len() {
        return false;
    }

    true
}

/// How to handle expired trust bundles
#[derive(Debug, Clone, Default)]
pub enum GracePeriodBehavior {
    /// Fail immediately when bundle expires
    Strict,

    /// Allow with warnings during grace period, then fail
    #[default]
    WarnDuringGrace,

    /// Always allow with warnings (never hard fail due to expiry)
    WarnOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AirGappedConfig::default();
        assert!(config.max_signature_age.is_none());
        assert!(config.check_revocations);
        assert!(!config.enforce_rollback_protection);
    }

    #[test]
    fn test_high_security_config() {
        let config = AirGappedConfig::high_security();
        assert!(config.max_signature_age.is_some());
        assert!(config.enforce_rollback_protection);
        assert!(matches!(config.grace_period_behavior, GracePeriodBehavior::Strict));
    }

    #[test]
    fn test_identity_requirements_exact_match() {
        let req = IdentityRequirements {
            allowed_issuers: vec!["https://issuer.example.com".to_string()],
            allowed_subjects: vec!["user@example.com".to_string()],
        };

        assert!(req.matches_issuer("https://issuer.example.com"));
        assert!(!req.matches_issuer("https://other.example.com"));

        assert!(req.matches_subject("user@example.com"));
        assert!(!req.matches_subject("other@example.com"));
    }

    #[test]
    fn test_identity_requirements_glob_match() {
        let req = IdentityRequirements::github_actions("myorg");

        assert!(req.matches_issuer("https://token.actions.githubusercontent.com"));
        assert!(req.matches_subject("https://github.com/myorg/repo/.github/workflows/ci.yml@refs/heads/main"));
        assert!(!req.matches_subject("https://github.com/otherorg/repo"));
    }

    #[test]
    fn test_glob_match() {
        assert!(glob_match("hello*", "hello world"));
        assert!(glob_match("*world", "hello world"));
        assert!(glob_match("hello*world", "hello beautiful world"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("exact", "exact"));

        assert!(!glob_match("hello*", "world hello"));
        assert!(!glob_match("*world", "world hello"));
        assert!(!glob_match("exact", "not exact"));
    }
}
