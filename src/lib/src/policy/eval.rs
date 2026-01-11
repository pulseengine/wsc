//! Policy evaluation engine.
//!
//! This module provides the core policy evaluation logic that checks
//! transformation attestations against supply chain policies.

use super::{Enforcement, Policy, SlsaPolicy};
use super::slsa::{SlsaLevel, detect_slsa_level_detailed, SlsaLevelAnalysis};
use wsc_attestation::{TransformationAttestation, SignatureStatus};

// ============================================================================
// Evaluation Result Types
// ============================================================================

/// Result of evaluating a single policy rule.
#[derive(Debug, Clone)]
pub struct RuleResult {
    /// Rule identifier (e.g., "slsa.minimum_level", "signatures.attestation")
    pub rule: String,

    /// Whether the rule passed
    pub passed: bool,

    /// Enforcement mode for this rule
    pub enforcement: Enforcement,

    /// Human-readable message explaining the result
    pub message: String,

    /// Optional additional details
    pub details: Option<String>,
}

impl RuleResult {
    fn pass(rule: impl Into<String>, enforcement: Enforcement, message: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            passed: true,
            enforcement,
            message: message.into(),
            details: None,
        }
    }

    fn fail(rule: impl Into<String>, enforcement: Enforcement, message: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            passed: false,
            enforcement,
            message: message.into(),
            details: None,
        }
    }

    fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Returns true if this failure should cause overall policy to fail
    pub fn causes_failure(&self) -> bool {
        !self.passed && self.enforcement == Enforcement::Strict
    }
}

/// Summary statistics for policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicySummary {
    /// Total number of rules evaluated
    pub total_rules: usize,

    /// Number of rules that passed
    pub passed: usize,

    /// Number of strict rules that failed (caused overall failure)
    pub failed_strict: usize,

    /// Number of report-only rules that failed (warnings)
    pub failed_report: usize,

    /// Detected SLSA level
    pub slsa_level: SlsaLevel,

    /// Names of tools that were verified
    pub tools_verified: Vec<String>,

    /// SLSA level analysis details
    pub slsa_analysis: Option<SlsaLevelAnalysis>,
}

/// Complete result of policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyEvaluationResult {
    /// Whether the policy passed overall
    ///
    /// This is true only if all rules with `Strict` enforcement passed.
    /// Rules with `Report` enforcement don't affect this.
    pub passed: bool,

    /// Detected SLSA level of the attestation
    pub slsa_level: SlsaLevel,

    /// Individual rule results
    pub rules: Vec<RuleResult>,

    /// Summary statistics
    pub summary: PolicySummary,
}

impl PolicyEvaluationResult {
    /// Get all failed rules (regardless of enforcement mode).
    pub fn failed_rules(&self) -> impl Iterator<Item = &RuleResult> {
        self.rules.iter().filter(|r| !r.passed)
    }

    /// Get only strict failures (rules that caused overall failure).
    pub fn strict_failures(&self) -> impl Iterator<Item = &RuleResult> {
        self.rules.iter().filter(|r| r.causes_failure())
    }

    /// Get only report failures (warnings that didn't fail the policy).
    pub fn report_failures(&self) -> impl Iterator<Item = &RuleResult> {
        self.rules.iter().filter(|r| !r.passed && r.enforcement == Enforcement::Report)
    }

    /// Get suggestions for improving SLSA level.
    pub fn slsa_suggestions(&self) -> Vec<String> {
        self.summary.slsa_analysis
            .as_ref()
            .map(|a| a.suggestions_for_next_level())
            .unwrap_or_default()
    }
}

// ============================================================================
// Policy Evaluation
// ============================================================================

/// Evaluate a transformation attestation against a policy.
///
/// This is the main entry point for policy evaluation. It checks all policy
/// rules against the attestation and returns a comprehensive result.
///
/// # Arguments
///
/// * `attestation` - The transformation attestation to evaluate
/// * `policy` - The policy to check against
///
/// # Returns
///
/// A `PolicyEvaluationResult` containing the overall pass/fail status,
/// individual rule results, and summary statistics.
///
/// # Example
///
/// ```rust,ignore
/// use wsc::policy::{Policy, evaluate_policy};
///
/// let policy = Policy::from_toml_file("wsc-policy.toml")?;
/// let result = evaluate_policy(&attestation, &policy);
///
/// if result.passed {
///     println!("Policy passed! SLSA Level: {}", result.slsa_level);
/// } else {
///     for failure in result.strict_failures() {
///         eprintln!("FAILED: {} - {}", failure.rule, failure.message);
///     }
/// }
/// ```
pub fn evaluate_policy(
    attestation: &TransformationAttestation,
    policy: &Policy,
) -> PolicyEvaluationResult {
    let mut rules = Vec::new();
    let mut tools_verified = Vec::new();

    // Detect SLSA level
    let slsa_analysis = detect_slsa_level_detailed(attestation);
    let slsa_level = slsa_analysis.level;

    // Check SLSA minimum level
    rules.push(check_slsa_level(&slsa_analysis, &policy.slsa, policy));

    // Check signature requirements
    rules.extend(check_signatures(attestation, policy));

    // Check trusted tools
    if let Some(result) = check_trusted_tool(attestation, policy) {
        if result.passed {
            tools_verified.push(attestation.tool.name.clone());
        }
        rules.push(result);
    }

    // Check attestation age
    if let Some(result) = check_attestation_age(attestation, policy) {
        rules.push(result);
    }

    // Calculate summary
    let total_rules = rules.len();
    let passed_count = rules.iter().filter(|r| r.passed).count();
    let failed_strict = rules.iter().filter(|r| r.causes_failure()).count();
    let failed_report = rules.iter().filter(|r| !r.passed && r.enforcement == Enforcement::Report).count();

    let summary = PolicySummary {
        total_rules,
        passed: passed_count,
        failed_strict,
        failed_report,
        slsa_level,
        tools_verified,
        slsa_analysis: Some(slsa_analysis),
    };

    let overall_passed = failed_strict == 0;

    PolicyEvaluationResult {
        passed: overall_passed,
        slsa_level,
        rules,
        summary,
    }
}

// ============================================================================
// Individual Rule Checks
// ============================================================================

/// Check SLSA level requirement.
fn check_slsa_level(
    analysis: &SlsaLevelAnalysis,
    slsa_policy: &SlsaPolicy,
    policy: &Policy,
) -> RuleResult {
    let enforcement = policy.effective_enforcement(slsa_policy.enforcement);
    let required = SlsaLevel::from_u8(slsa_policy.minimum_level);
    let detected = analysis.level;

    if detected >= required {
        RuleResult::pass(
            "slsa.minimum_level",
            enforcement,
            format!("Detected {} meets requirement of {}", detected, required),
        ).with_details(analysis.reasons.join("; "))
    } else {
        RuleResult::fail(
            "slsa.minimum_level",
            enforcement,
            format!("Detected {} does not meet requirement of {}", detected, required),
        ).with_details(analysis.reasons.join("; "))
    }
}

/// Check signature requirements.
fn check_signatures(
    attestation: &TransformationAttestation,
    policy: &Policy,
) -> Vec<RuleResult> {
    let mut results = Vec::new();
    let enforcement = policy.effective_enforcement(policy.signatures.enforcement);

    // Check attestation signature requirement
    if policy.signatures.require_attestation_signatures {
        let is_signed = attestation.attestation_signature.algorithm != "unsigned"
            && !attestation.attestation_signature.signature.is_empty();

        if is_signed {
            let algo = &attestation.attestation_signature.algorithm;
            let key_info = attestation.attestation_signature.key_id
                .as_ref()
                .map(|k| format!(" (key: {})", k))
                .or_else(|| attestation.attestation_signature.signer_identity
                    .as_ref()
                    .map(|s| format!(" (identity: {})", s)))
                .unwrap_or_default();

            results.push(RuleResult::pass(
                "signatures.attestation",
                enforcement,
                format!("Attestation signed with {}{}", algo, key_info),
            ));
        } else {
            results.push(RuleResult::fail(
                "signatures.attestation",
                enforcement,
                "Attestation is not signed but policy requires attestation signatures",
            ));
        }
    }

    // Check root signature requirement
    if policy.signatures.require_root_signatures {
        let all_verified = attestation.inputs.iter()
            .all(|i| i.signature_status == SignatureStatus::Verified);
        let any_verified = attestation.inputs.iter()
            .any(|i| i.signature_status == SignatureStatus::Verified);

        if all_verified && !attestation.inputs.is_empty() {
            results.push(RuleResult::pass(
                "signatures.root",
                enforcement,
                format!("All {} input(s) have verified signatures", attestation.inputs.len()),
            ));
        } else if any_verified {
            let verified_count = attestation.inputs.iter()
                .filter(|i| i.signature_status == SignatureStatus::Verified)
                .count();
            results.push(RuleResult::fail(
                "signatures.root",
                enforcement,
                format!("Only {} of {} inputs have verified signatures",
                    verified_count, attestation.inputs.len()),
            ));
        } else {
            results.push(RuleResult::fail(
                "signatures.root",
                enforcement,
                "No input artifacts have verified signatures",
            ));
        }
    }

    results
}

/// Check trusted tool requirement.
fn check_trusted_tool(
    attestation: &TransformationAttestation,
    policy: &Policy,
) -> Option<RuleResult> {
    let tool_name = &attestation.tool.name;

    if policy.trusted_tools.is_empty() {
        // No trusted tools policy - skip check
        return None;
    }

    let tool_policy = policy.trusted_tools.get(tool_name);

    if let Some(tp) = tool_policy {
        let enforcement = policy.effective_enforcement(tp.enforcement);

        // Check version constraint if specified
        if let Some(ref min_version) = tp.min_version {
            if !version_meets_minimum(&attestation.tool.version, min_version) {
                return Some(RuleResult::fail(
                    format!("trusted_tools.{}.version", tool_name),
                    enforcement,
                    format!("Tool version {} does not meet minimum {}",
                        attestation.tool.version, min_version),
                ));
            }
        }

        if let Some(ref max_version) = tp.max_version {
            if !version_below_maximum(&attestation.tool.version, max_version) {
                return Some(RuleResult::fail(
                    format!("trusted_tools.{}.version", tool_name),
                    enforcement,
                    format!("Tool version {} exceeds maximum {}",
                        attestation.tool.version, max_version),
                ));
            }
        }

        // Check tool hash if specified
        if let Some(ref required_hash) = tp.required_hash {
            match &attestation.tool.tool_hash {
                Some(actual_hash) if actual_hash == required_hash => {
                    // Hash matches
                }
                Some(actual_hash) => {
                    return Some(RuleResult::fail(
                        format!("trusted_tools.{}.hash", tool_name),
                        enforcement,
                        format!("Tool hash {} does not match required {}",
                            actual_hash, required_hash),
                    ));
                }
                None => {
                    return Some(RuleResult::fail(
                        format!("trusted_tools.{}.hash", tool_name),
                        enforcement,
                        "Tool hash required but not provided in attestation",
                    ));
                }
            }
        }

        Some(RuleResult::pass(
            format!("trusted_tools.{}", tool_name),
            enforcement,
            format!("Tool '{}' version {} is trusted", tool_name, attestation.tool.version),
        ))
    } else {
        // Tool not in trusted list - this is a failure
        let enforcement = policy.policy.enforcement;
        Some(RuleResult::fail(
            "trusted_tools",
            enforcement,
            format!("Tool '{}' is not in the trusted tools list", tool_name),
        ))
    }
}

/// Check attestation age.
fn check_attestation_age(
    attestation: &TransformationAttestation,
    policy: &Policy,
) -> Option<RuleResult> {
    let max_age = policy.signatures.max_attestation_age()?;
    let enforcement = policy.effective_enforcement(policy.signatures.enforcement);

    // Parse the attestation timestamp
    let attestation_time = chrono::DateTime::parse_from_rfc3339(&attestation.timestamp)
        .ok()?;
    let now = chrono::Utc::now();
    let age = now.signed_duration_since(attestation_time);

    if age.num_seconds() < 0 {
        // Future timestamp - suspicious
        return Some(RuleResult::fail(
            "signatures.attestation_age",
            enforcement,
            "Attestation timestamp is in the future",
        ));
    }

    let max_age_secs = max_age.as_secs() as i64;
    if age.num_seconds() > max_age_secs {
        let days = age.num_days();
        let max_days = max_age_secs / (24 * 60 * 60);
        Some(RuleResult::fail(
            "signatures.attestation_age",
            enforcement,
            format!("Attestation is {} days old, maximum allowed is {} days", days, max_days),
        ))
    } else {
        let days = age.num_days();
        Some(RuleResult::pass(
            "signatures.attestation_age",
            enforcement,
            format!("Attestation is {} days old (max: {} days)", days, max_age.as_secs() / (24 * 60 * 60)),
        ))
    }
}

// ============================================================================
// Version Comparison Helpers
// ============================================================================

/// Check if version meets minimum (simple semver comparison).
fn version_meets_minimum(actual: &str, minimum: &str) -> bool {
    compare_versions(actual, minimum) >= 0
}

/// Check if version is below maximum (simple semver comparison).
fn version_below_maximum(actual: &str, maximum: &str) -> bool {
    compare_versions(actual, maximum) <= 0
}

/// Compare two semver-like version strings.
/// Returns: -1 if a < b, 0 if a == b, 1 if a > b
fn compare_versions(a: &str, b: &str) -> i32 {
    let parse = |v: &str| -> Vec<u32> {
        v.split('.')
            .filter_map(|s| s.split('-').next()) // Handle pre-release
            .filter_map(|s| s.parse().ok())
            .collect()
    };

    let va = parse(a);
    let vb = parse(b);
    let max_len = va.len().max(vb.len());

    for i in 0..max_len {
        let pa = va.get(i).copied().unwrap_or(0);
        let pb = vb.get(i).copied().unwrap_or(0);
        if pa < pb {
            return -1;
        }
        if pa > pb {
            return 1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsc_attestation::TransformationAttestationBuilder;

    fn create_test_attestation() -> TransformationAttestation {
        TransformationAttestationBuilder::new_optimization("loom", "0.2.0")
            .add_input_unsigned(b"input", "input.wasm")
            .build(b"output", "output.wasm")
    }

    #[test]
    fn test_evaluate_permissive_policy() {
        let attestation = create_test_attestation();
        let policy = Policy::permissive();

        let result = evaluate_policy(&attestation, &policy);

        // Permissive policy should pass with warnings
        assert!(result.passed, "Permissive policy should always pass");
        assert_eq!(result.slsa_level, SlsaLevel::L1); // Unsigned attestation
    }

    #[test]
    fn test_evaluate_strict_policy_fails() {
        let attestation = create_test_attestation();
        let policy = Policy::strict();

        let result = evaluate_policy(&attestation, &policy);

        // Strict policy should fail for unsigned attestation
        assert!(!result.passed, "Strict policy should fail for unsigned attestation");
        assert!(result.summary.failed_strict > 0);
    }

    #[test]
    fn test_slsa_level_check() {
        let attestation = create_test_attestation();

        // Policy requiring L1 should pass
        let mut policy = Policy::permissive();
        policy.slsa.minimum_level = 1;
        policy.slsa.enforcement = Some(Enforcement::Strict);

        let result = evaluate_policy(&attestation, &policy);
        let slsa_rule = result.rules.iter().find(|r| r.rule == "slsa.minimum_level").unwrap();
        assert!(slsa_rule.passed);

        // Policy requiring L2 should fail
        policy.slsa.minimum_level = 2;
        let result = evaluate_policy(&attestation, &policy);
        let slsa_rule = result.rules.iter().find(|r| r.rule == "slsa.minimum_level").unwrap();
        assert!(!slsa_rule.passed);
    }

    #[test]
    fn test_trusted_tool_check() {
        let attestation = create_test_attestation();
        let mut policy = Policy::permissive();

        // Add loom to trusted tools
        policy.add_trusted_tool("loom", crate::policy::TrustedToolPolicy {
            min_version: Some("0.1.0".to_string()),
            max_version: None,
            required_hash: None,
            public_keys: vec![],
            keyless: None,
            enforcement: Some(Enforcement::Strict),
        });

        let result = evaluate_policy(&attestation, &policy);
        let tool_rule = result.rules.iter().find(|r| r.rule.starts_with("trusted_tools")).unwrap();
        assert!(tool_rule.passed);
        assert!(result.summary.tools_verified.contains(&"loom".to_string()));
    }

    #[test]
    fn test_untrusted_tool_fails() {
        let attestation = create_test_attestation(); // Uses "loom"
        let mut policy = Policy::permissive();
        policy.policy.enforcement = Enforcement::Strict;

        // Only trust "wac", not "loom"
        policy.add_trusted_tool("wac", crate::policy::TrustedToolPolicy::default());

        let result = evaluate_policy(&attestation, &policy);
        let tool_rule = result.rules.iter().find(|r| r.rule == "trusted_tools").unwrap();
        assert!(!tool_rule.passed);
        assert!(tool_rule.message.contains("not in the trusted tools list"));
    }

    #[test]
    fn test_version_comparison() {
        assert!(version_meets_minimum("1.0.0", "1.0.0"));
        assert!(version_meets_minimum("1.1.0", "1.0.0"));
        assert!(version_meets_minimum("2.0.0", "1.0.0"));
        assert!(!version_meets_minimum("0.9.0", "1.0.0"));

        assert!(version_below_maximum("1.0.0", "1.0.0"));
        assert!(version_below_maximum("0.9.0", "1.0.0"));
        assert!(!version_below_maximum("1.1.0", "1.0.0"));
    }

    #[test]
    fn test_version_minimum_fails() {
        let attestation = create_test_attestation(); // loom 0.2.0
        let mut policy = Policy::permissive();

        policy.add_trusted_tool("loom", crate::policy::TrustedToolPolicy {
            min_version: Some("0.3.0".to_string()), // Higher than 0.2.0
            ..Default::default()
        });
        policy.policy.enforcement = Enforcement::Strict;

        let result = evaluate_policy(&attestation, &policy);
        assert!(!result.passed);
    }

    #[test]
    fn test_report_mode_doesnt_fail() {
        let attestation = create_test_attestation();
        let mut policy = Policy::permissive();
        policy.slsa.minimum_level = 4; // Impossible to meet
        policy.slsa.enforcement = Some(Enforcement::Report); // But report only

        let result = evaluate_policy(&attestation, &policy);
        assert!(result.passed); // Should still pass overall
        assert!(result.summary.failed_report > 0); // But with warnings
    }

    #[test]
    fn test_policy_summary() {
        let attestation = create_test_attestation();
        let policy = Policy::strict();

        let result = evaluate_policy(&attestation, &policy);

        assert!(result.summary.total_rules > 0);
        assert_eq!(result.summary.slsa_level, SlsaLevel::L1);
    }

    #[test]
    fn test_strict_failures_iterator() {
        let attestation = create_test_attestation();
        let policy = Policy::strict();

        let result = evaluate_policy(&attestation, &policy);
        let strict_failures: Vec<_> = result.strict_failures().collect();

        assert!(!strict_failures.is_empty());
        for failure in strict_failures {
            assert!(!failure.passed);
            assert_eq!(failure.enforcement, Enforcement::Strict);
        }
    }
}
