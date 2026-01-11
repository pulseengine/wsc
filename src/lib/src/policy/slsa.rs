//! SLSA (Supply chain Levels for Software Artifacts) level detection.
//!
//! This module provides functionality to detect the SLSA compliance level
//! of transformation attestations based on their properties.
//!
//! # SLSA Levels
//!
//! | Level | Requirements |
//! |-------|--------------|
//! | L0 | No protection |
//! | L1 | Provenance exists (attestation present) |
//! | L2 | Signed provenance from hosted build |
//! | L3 | Hardened build, non-forgeable provenance |
//! | L4 | Hermetic build, all inputs pinned |
//!
//! # Example
//!
//! ```rust,ignore
//! use wsc::policy::slsa::{SlsaLevel, detect_slsa_level};
//!
//! let level = detect_slsa_level(&attestation);
//! if level >= SlsaLevel::L2 {
//!     println!("Meets minimum production requirements");
//! }
//! ```

use serde::{Deserialize, Serialize};
use wsc_attestation::{SignatureStatus, TransformationAttestation};

/// SLSA compliance levels.
///
/// Higher levels provide stronger supply chain security guarantees.
/// Each level includes all requirements of lower levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SlsaLevel {
    /// L0: No protection
    ///
    /// No provenance or supply chain controls.
    L0 = 0,

    /// L1: Provenance exists
    ///
    /// Attestation is present but may be unsigned.
    /// Provides documentation of the build process.
    L1 = 1,

    /// L2: Signed provenance from hosted build
    ///
    /// Attestation is signed, providing integrity.
    /// Builder identity is established.
    L2 = 2,

    /// L3: Hardened build
    ///
    /// Non-forgeable provenance (transparency log).
    /// Protects against most supply chain attacks.
    L3 = 3,

    /// L4: Hermetic build
    ///
    /// All inputs are verified and pinned.
    /// Reproducible builds with complete provenance.
    L4 = 4,
}

impl SlsaLevel {
    /// Get the numeric value of the level.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Create from numeric value, clamping to valid range.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => SlsaLevel::L0,
            1 => SlsaLevel::L1,
            2 => SlsaLevel::L2,
            3 => SlsaLevel::L3,
            _ => SlsaLevel::L4,
        }
    }

    /// Get human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            SlsaLevel::L0 => "No protection",
            SlsaLevel::L1 => "Provenance exists",
            SlsaLevel::L2 => "Signed provenance",
            SlsaLevel::L3 => "Hardened build",
            SlsaLevel::L4 => "Hermetic build",
        }
    }

    /// Check if this level meets or exceeds a requirement.
    pub fn meets(&self, required: SlsaLevel) -> bool {
        *self >= required
    }
}

impl std::fmt::Display for SlsaLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SLSA L{}", self.as_u8())
    }
}

impl Default for SlsaLevel {
    fn default() -> Self {
        SlsaLevel::L0
    }
}

/// Detailed breakdown of SLSA level detection.
#[derive(Debug, Clone)]
pub struct SlsaLevelAnalysis {
    /// Detected SLSA level
    pub level: SlsaLevel,

    /// Whether provenance (attestation) exists
    pub has_provenance: bool,

    /// Whether provenance is signed
    pub is_signed: bool,

    /// Whether builder identity is established
    pub has_builder_identity: bool,

    /// Whether provenance is logged to transparency log
    pub has_transparency_log: bool,

    /// Whether all inputs are verified/pinned
    pub all_inputs_pinned: bool,

    /// Reasons for the detected level
    pub reasons: Vec<String>,
}

impl SlsaLevelAnalysis {
    /// Get suggestions for reaching the next level.
    pub fn suggestions_for_next_level(&self) -> Vec<String> {
        match self.level {
            SlsaLevel::L0 => vec!["Add transformation attestation to the module".to_string()],
            SlsaLevel::L1 => vec![
                "Sign the attestation with a trusted key".to_string(),
                "Use keyless signing with OIDC identity".to_string(),
            ],
            SlsaLevel::L2 => vec![
                "Log signature to Rekor transparency log".to_string(),
                "Use Sigstore keyless signing".to_string(),
            ],
            SlsaLevel::L3 => vec![
                "Ensure all input components have verified signatures".to_string(),
                "Pin all dependencies with cryptographic hashes".to_string(),
            ],
            SlsaLevel::L4 => vec![], // Already at max
        }
    }
}

/// Detect the SLSA compliance level of a transformation attestation.
///
/// This function analyzes the attestation's properties to determine
/// which SLSA level requirements are satisfied.
///
/// # Arguments
///
/// * `attestation` - The transformation attestation to analyze
///
/// # Returns
///
/// The detected SLSA level (L0-L4)
pub fn detect_slsa_level(attestation: &TransformationAttestation) -> SlsaLevel {
    detect_slsa_level_detailed(attestation).level
}

/// Detect SLSA level with detailed analysis.
///
/// Provides a breakdown of which requirements are met and why.
pub fn detect_slsa_level_detailed(attestation: &TransformationAttestation) -> SlsaLevelAnalysis {
    let mut analysis = SlsaLevelAnalysis {
        level: SlsaLevel::L0,
        has_provenance: true, // We have an attestation
        is_signed: false,
        has_builder_identity: false,
        has_transparency_log: false,
        all_inputs_pinned: false,
        reasons: Vec::new(),
    };

    // L1: Provenance exists (we have an attestation)
    analysis.reasons.push("Attestation present → L1".to_string());
    analysis.level = SlsaLevel::L1;

    // L2: Signed provenance from hosted build
    let is_signed = attestation.attestation_signature.algorithm != "unsigned"
        && !attestation.attestation_signature.signature.is_empty();

    let has_builder_identity = attestation.attestation_signature.signer_identity.is_some()
        || attestation.attestation_signature.certificate_chain.is_some()
        || attestation.attestation_signature.public_key.is_some();

    analysis.is_signed = is_signed;
    analysis.has_builder_identity = has_builder_identity;

    if is_signed && has_builder_identity {
        analysis.reasons.push("Signed with builder identity → L2".to_string());
        analysis.level = SlsaLevel::L2;
    } else if is_signed {
        analysis.reasons.push("Signed but no builder identity → L1".to_string());
    }

    // L3: Hardened build (non-forgeable provenance via transparency log)
    let has_rekor = attestation.attestation_signature.rekor_uuid.is_some();
    analysis.has_transparency_log = has_rekor;

    if has_rekor && is_signed {
        analysis.reasons.push("Logged to Rekor transparency log → L3".to_string());
        analysis.level = SlsaLevel::L3;
    }

    // L4: Hermetic build (all inputs verified)
    let all_inputs_verified = !attestation.inputs.is_empty()
        && attestation.inputs.iter().all(|input| {
            input.signature_status == SignatureStatus::Verified
        });

    analysis.all_inputs_pinned = all_inputs_verified;

    if all_inputs_verified && has_rekor && is_signed {
        analysis.reasons.push("All inputs verified → L4".to_string());
        analysis.level = SlsaLevel::L4;
    } else if !attestation.inputs.is_empty() && !all_inputs_verified {
        let unverified_count = attestation
            .inputs
            .iter()
            .filter(|i| i.signature_status != SignatureStatus::Verified)
            .count();
        analysis.reasons.push(format!(
            "{} of {} inputs not verified (blocks L4)",
            unverified_count,
            attestation.inputs.len()
        ));
    }

    analysis
}

/// Check if an attestation meets a minimum SLSA level requirement.
pub fn meets_slsa_level(attestation: &TransformationAttestation, required: SlsaLevel) -> bool {
    detect_slsa_level(attestation) >= required
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsc_attestation::TransformationAttestationBuilder;

    fn create_unsigned_attestation() -> TransformationAttestation {
        TransformationAttestationBuilder::new_optimization("test-tool", "1.0.0")
            .add_input_unsigned(b"input", "input.wasm")
            .build(b"output", "output.wasm")
    }

    #[test]
    fn test_slsa_level_ordering() {
        assert!(SlsaLevel::L0 < SlsaLevel::L1);
        assert!(SlsaLevel::L1 < SlsaLevel::L2);
        assert!(SlsaLevel::L2 < SlsaLevel::L3);
        assert!(SlsaLevel::L3 < SlsaLevel::L4);
    }

    #[test]
    fn test_slsa_level_display() {
        assert_eq!(SlsaLevel::L0.to_string(), "SLSA L0");
        assert_eq!(SlsaLevel::L3.to_string(), "SLSA L3");
    }

    #[test]
    fn test_slsa_level_from_u8() {
        assert_eq!(SlsaLevel::from_u8(0), SlsaLevel::L0);
        assert_eq!(SlsaLevel::from_u8(2), SlsaLevel::L2);
        assert_eq!(SlsaLevel::from_u8(99), SlsaLevel::L4); // Clamps to max
    }

    #[test]
    fn test_slsa_level_meets() {
        assert!(SlsaLevel::L3.meets(SlsaLevel::L2));
        assert!(SlsaLevel::L2.meets(SlsaLevel::L2));
        assert!(!SlsaLevel::L1.meets(SlsaLevel::L2));
    }

    #[test]
    fn test_detect_unsigned_attestation_l1() {
        let attestation = create_unsigned_attestation();
        let level = detect_slsa_level(&attestation);

        // Unsigned attestation = L1 (provenance exists but not signed)
        assert_eq!(level, SlsaLevel::L1);
    }

    #[test]
    fn test_detailed_analysis() {
        let attestation = create_unsigned_attestation();
        let analysis = detect_slsa_level_detailed(&attestation);

        assert!(analysis.has_provenance);
        assert!(!analysis.is_signed);
        assert!(!analysis.has_transparency_log);
        assert!(!analysis.all_inputs_pinned);
        assert!(!analysis.reasons.is_empty());
    }

    #[test]
    fn test_suggestions_for_next_level() {
        let analysis = SlsaLevelAnalysis {
            level: SlsaLevel::L1,
            has_provenance: true,
            is_signed: false,
            has_builder_identity: false,
            has_transparency_log: false,
            all_inputs_pinned: false,
            reasons: vec![],
        };

        let suggestions = analysis.suggestions_for_next_level();
        assert!(!suggestions.is_empty());
        assert!(suggestions.iter().any(|s| s.contains("Sign")));
    }

    #[test]
    fn test_meets_slsa_level() {
        let attestation = create_unsigned_attestation();

        assert!(meets_slsa_level(&attestation, SlsaLevel::L0));
        assert!(meets_slsa_level(&attestation, SlsaLevel::L1));
        assert!(!meets_slsa_level(&attestation, SlsaLevel::L2));
    }
}
