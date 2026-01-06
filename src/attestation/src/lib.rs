//! # WSC Attestation
//!
//! Minimal crate providing transformation attestation types for WebAssembly toolchains.
//!
//! This crate is designed to be lightweight so that tools like optimizers (Loom)
//! and composers (WAC) can add transformation attestations without pulling in
//! heavy cryptographic dependencies.
//!
//! ## Use Cases
//!
//! - **Optimizers** (Loom, wasm-opt): Record what was optimized and how
//! - **Composers** (WAC): Record what components were combined
//! - **Instrumenters**: Record what instrumentation was added
//!
//! ## Example
//!
//! ```rust
//! use wsc_attestation::*;
//!
//! // Create an attestation for an optimization transformation
//! let attestation = TransformationAttestationBuilder::new_optimization("loom", "0.1.0")
//!     .add_input_unsigned(b"input wasm bytes", "input.wasm")
//!     .add_parameter("opt_level", serde_json::json!("aggressive"))
//!     .build(b"output wasm bytes", "output.wasm");
//!
//! // Serialize to JSON for embedding in WASM custom section
//! let json = attestation.to_json().unwrap();
//!
//! // The JSON can be embedded in a custom section named:
//! assert_eq!(TRANSFORMATION_ATTESTATION_SECTION, "wsc.transformation.attestation");
//! ```
//!
//! ## WASM Custom Section Names
//!
//! This crate defines the standard section names but does NOT provide
//! WASM parsing/embedding. Tools should use their own WASM libraries
//! (wasmparser, wasm-encoder, etc.) to embed the JSON.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Section Name Constants
// ============================================================================

/// Custom section name for transformation attestation
pub const TRANSFORMATION_ATTESTATION_SECTION: &str = "wsc.transformation.attestation";

/// Custom section name for full transformation audit trail
pub const TRANSFORMATION_AUDIT_TRAIL_SECTION: &str = "wsc.transformation.audit_trail";

// ============================================================================
// Build Provenance
// ============================================================================

/// Build provenance for a WASM component
///
/// Captures information about how a component was built, following
/// the SLSA provenance format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildProvenance {
    /// Component name
    pub name: String,

    /// Component version (semver)
    pub version: String,

    /// Source repository URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_repo: Option<String>,

    /// Git commit SHA
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,

    /// Build tool name (e.g., "cargo", "wasm-pack")
    pub build_tool: String,

    /// Build tool version
    pub build_tool_version: String,

    /// Builder identity (CI system, developer, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder: Option<String>,

    /// Build timestamp (ISO 8601)
    pub build_timestamp: String,

    /// Additional metadata
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub metadata: HashMap<String, String>,
}

/// Builder for creating BuildProvenance
pub struct ProvenanceBuilder {
    name: Option<String>,
    version: Option<String>,
    source_repo: Option<String>,
    commit_sha: Option<String>,
    build_tool: Option<String>,
    build_tool_version: Option<String>,
    builder: Option<String>,
    metadata: HashMap<String, String>,
}

impl ProvenanceBuilder {
    pub fn new() -> Self {
        Self {
            name: None,
            version: None,
            source_repo: None,
            commit_sha: None,
            build_tool: None,
            build_tool_version: None,
            builder: None,
            metadata: HashMap::new(),
        }
    }

    pub fn component_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn source_repo(mut self, repo: impl Into<String>) -> Self {
        self.source_repo = Some(repo.into());
        self
    }

    pub fn commit_sha(mut self, sha: impl Into<String>) -> Self {
        self.commit_sha = Some(sha.into());
        self
    }

    pub fn build_tool(mut self, tool: impl Into<String>, version: impl Into<String>) -> Self {
        self.build_tool = Some(tool.into());
        self.build_tool_version = Some(version.into());
        self
    }

    pub fn builder_identity(mut self, builder: impl Into<String>) -> Self {
        self.builder = Some(builder.into());
        self
    }

    pub fn add_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> BuildProvenance {
        BuildProvenance {
            name: self.name.unwrap_or_else(|| "unknown".to_string()),
            version: self.version.unwrap_or_else(|| "0.0.0".to_string()),
            source_repo: self.source_repo,
            commit_sha: self.commit_sha,
            build_tool: self.build_tool.unwrap_or_else(|| "unknown".to_string()),
            build_tool_version: self
                .build_tool_version
                .unwrap_or_else(|| "unknown".to_string()),
            builder: self.builder,
            build_timestamp: chrono::Utc::now().to_rfc3339(),
            metadata: self.metadata,
        }
    }
}

impl Default for ProvenanceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Core Types
// ============================================================================

/// Type of transformation performed on a WASM module
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformationType {
    /// Optimization (e.g., Loom, wasm-opt)
    Optimization,
    /// Composition (e.g., WAC, wit-bindgen)
    Composition,
    /// Instrumentation (e.g., adding tracing, coverage)
    Instrumentation,
    /// Stripping (e.g., removing debug info)
    Stripping,
    /// Custom transformation
    Custom,
}

impl std::fmt::Display for TransformationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransformationType::Optimization => write!(f, "optimization"),
            TransformationType::Composition => write!(f, "composition"),
            TransformationType::Instrumentation => write!(f, "instrumentation"),
            TransformationType::Stripping => write!(f, "stripping"),
            TransformationType::Custom => write!(f, "custom"),
        }
    }
}

/// Descriptor for an artifact (input or output of transformation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactDescriptor {
    /// Name or path of the artifact
    pub name: String,

    /// SHA-256 hash of the artifact (hex encoded)
    pub hash: String,

    /// Size in bytes
    pub size: u64,
}

/// Status of a signature on an input artifact
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Signature was verified successfully
    Verified,
    /// Signature exists but was not verified (e.g., missing public key)
    SignedUnverified,
    /// No signature present
    Unsigned,
}

impl std::fmt::Display for SignatureStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureStatus::Verified => write!(f, "verified"),
            SignatureStatus::SignedUnverified => write!(f, "signed_unverified"),
            SignatureStatus::Unsigned => write!(f, "unsigned"),
        }
    }
}

/// Information about a signature on an input artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSignatureInfo {
    /// Key ID that signed this artifact (if key-based)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// Signer identity from certificate (if keyless)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_identity: Option<String>,

    /// Signature algorithm used
    pub algorithm: String,

    /// Timestamp of signature (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,

    /// Rekor log entry UUID (if logged)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekor_uuid: Option<String>,
}

/// Information about the transformation tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    /// Tool name (e.g., "loom", "wac", "wasm-opt")
    pub name: String,

    /// Tool version
    pub version: String,

    /// Hash of the tool binary (for reproducibility)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_hash: Option<String>,

    /// Additional tool-specific parameters used
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub parameters: HashMap<String, serde_json::Value>,
}

/// Signature on the attestation itself
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationSignature {
    /// Signature algorithm (e.g., "ed25519", "ecdsa-p256", "unsigned")
    pub algorithm: String,

    /// Base64-encoded signature (empty if unsigned)
    pub signature: String,

    /// Key ID of the signing key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// Signer identity from certificate (if keyless)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_identity: Option<String>,

    /// Timestamp of attestation signature (ISO 8601)
    pub signed_at: String,
}

/// An input artifact to a transformation, with signature and provenance info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputArtifact {
    /// Descriptor of the input artifact
    pub artifact: ArtifactDescriptor,

    /// Signature status of the input
    pub signature_status: SignatureStatus,

    /// Signature information (if signed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_info: Option<InputSignatureInfo>,

    /// Build provenance (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Box<BuildProvenance>>,

    /// Nested transformation chain (for multi-stage pipelines)
    /// If this input was itself the output of a transformation,
    /// this contains the attestation for that prior transformation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transformation_chain: Option<Box<TransformationAttestation>>,
}

/// Attestation for a single transformation step
///
/// This is the core structure for tracking transformations. Each time a tool
/// like Loom or WAC transforms a module, it generates a TransformationAttestation
/// that cryptographically links inputs to outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationAttestation {
    /// Schema version for forward compatibility
    pub version: String,

    /// Type of transformation performed
    pub transformation_type: TransformationType,

    /// Unique identifier for this attestation
    pub attestation_id: String,

    /// Timestamp when transformation was performed (ISO 8601)
    pub timestamp: String,

    /// Output artifact descriptor
    pub output: ArtifactDescriptor,

    /// Input artifacts with their signature status
    pub inputs: Vec<InputArtifact>,

    /// Information about the transformation tool
    pub tool: ToolInfo,

    /// Signature on this attestation
    pub attestation_signature: AttestationSignature,

    /// Additional metadata (e.g., optimization flags, composition strategy)
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl TransformationAttestation {
    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to compact JSON (no pretty printing)
    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// A root component in the audit trail (original signed component)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootComponent {
    /// Artifact descriptor
    pub artifact: ArtifactDescriptor,

    /// Original signature information
    pub signature_info: InputSignatureInfo,

    /// Original build provenance (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<BuildProvenance>,
}

/// Complete audit trail for a transformed artifact
///
/// This structure contains the full chain of transformations from
/// original signed components to the final artifact. It can be
/// embedded in the final WASM module for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationAuditTrail {
    /// Schema version
    pub version: String,

    /// Final output artifact
    pub artifact: ArtifactDescriptor,

    /// Ordered list of transformations (newest first)
    pub transformations: Vec<TransformationAttestation>,

    /// Original signed components at the root of the chain
    pub root_components: Vec<RootComponent>,

    /// Timestamp when audit trail was assembled
    pub assembled_at: String,
}

impl TransformationAuditTrail {
    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Count total transformations in the chain
    pub fn transformation_count(&self) -> usize {
        self.transformations.len()
    }

    /// Get all unique tool names used in transformations
    pub fn tools_used(&self) -> Vec<&str> {
        let mut tools: Vec<&str> = self
            .transformations
            .iter()
            .map(|t| t.tool.name.as_str())
            .collect();
        tools.sort();
        tools.dedup();
        tools
    }
}

// ============================================================================
// Builder
// ============================================================================

/// Builder for creating TransformationAttestation
///
/// This builder makes it easy for transformation tools (like Loom, WAC)
/// to create properly structured attestations.
pub struct TransformationAttestationBuilder {
    transformation_type: TransformationType,
    tool_name: String,
    tool_version: String,
    tool_hash: Option<String>,
    tool_parameters: HashMap<String, serde_json::Value>,
    inputs: Vec<InputArtifact>,
    metadata: HashMap<String, serde_json::Value>,
}

impl TransformationAttestationBuilder {
    /// Create a new builder for an optimization transformation
    pub fn new_optimization(tool_name: impl Into<String>, tool_version: impl Into<String>) -> Self {
        Self::new(TransformationType::Optimization, tool_name, tool_version)
    }

    /// Create a new builder for a composition transformation
    pub fn new_composition(tool_name: impl Into<String>, tool_version: impl Into<String>) -> Self {
        Self::new(TransformationType::Composition, tool_name, tool_version)
    }

    /// Create a new builder for an instrumentation transformation
    pub fn new_instrumentation(
        tool_name: impl Into<String>,
        tool_version: impl Into<String>,
    ) -> Self {
        Self::new(TransformationType::Instrumentation, tool_name, tool_version)
    }

    /// Create a new builder with a custom transformation type
    pub fn new(
        transformation_type: TransformationType,
        tool_name: impl Into<String>,
        tool_version: impl Into<String>,
    ) -> Self {
        Self {
            transformation_type,
            tool_name: tool_name.into(),
            tool_version: tool_version.into(),
            tool_hash: None,
            tool_parameters: HashMap::new(),
            inputs: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Set the hash of the transformation tool binary (for reproducibility)
    pub fn tool_hash(mut self, hash: impl Into<String>) -> Self {
        self.tool_hash = Some(hash.into());
        self
    }

    /// Add a tool parameter (e.g., optimization level, composition strategy)
    pub fn add_parameter(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.tool_parameters.insert(key.into(), value);
        self
    }

    /// Add metadata to the attestation
    pub fn add_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Add a verified input artifact
    ///
    /// Use this when the input module's signature was verified before transformation.
    pub fn add_input_verified(
        mut self,
        module_bytes: &[u8],
        name: impl Into<String>,
        signature_info: InputSignatureInfo,
    ) -> Self {
        let hash = compute_sha256_hash(module_bytes);
        self.inputs.push(InputArtifact {
            artifact: ArtifactDescriptor {
                name: name.into(),
                hash,
                size: module_bytes.len() as u64,
            },
            signature_status: SignatureStatus::Verified,
            signature_info: Some(signature_info),
            provenance: None,
            transformation_chain: None,
        });
        self
    }

    /// Add an input that was signed but not verified
    ///
    /// Use this when the input has a signature but verification wasn't performed
    /// (e.g., public key not available).
    pub fn add_input_signed_unverified(
        mut self,
        module_bytes: &[u8],
        name: impl Into<String>,
        signature_info: Option<InputSignatureInfo>,
    ) -> Self {
        let hash = compute_sha256_hash(module_bytes);
        self.inputs.push(InputArtifact {
            artifact: ArtifactDescriptor {
                name: name.into(),
                hash,
                size: module_bytes.len() as u64,
            },
            signature_status: SignatureStatus::SignedUnverified,
            signature_info,
            provenance: None,
            transformation_chain: None,
        });
        self
    }

    /// Add an unsigned input artifact
    pub fn add_input_unsigned(mut self, module_bytes: &[u8], name: impl Into<String>) -> Self {
        let hash = compute_sha256_hash(module_bytes);
        self.inputs.push(InputArtifact {
            artifact: ArtifactDescriptor {
                name: name.into(),
                hash,
                size: module_bytes.len() as u64,
            },
            signature_status: SignatureStatus::Unsigned,
            signature_info: None,
            provenance: None,
            transformation_chain: None,
        });
        self
    }

    /// Add an input with build provenance
    ///
    /// Use this when the input has build provenance information (SLSA).
    pub fn add_input_with_provenance(
        mut self,
        module_bytes: &[u8],
        name: impl Into<String>,
        signature_status: SignatureStatus,
        signature_info: Option<InputSignatureInfo>,
        provenance: BuildProvenance,
    ) -> Self {
        let hash = compute_sha256_hash(module_bytes);
        self.inputs.push(InputArtifact {
            artifact: ArtifactDescriptor {
                name: name.into(),
                hash,
                size: module_bytes.len() as u64,
            },
            signature_status,
            signature_info,
            provenance: Some(Box::new(provenance)),
            transformation_chain: None,
        });
        self
    }

    /// Add an input with a prior transformation chain
    ///
    /// Use this when the input was itself the output of a previous transformation.
    pub fn add_input_with_chain(
        mut self,
        module_bytes: &[u8],
        name: impl Into<String>,
        prior_attestation: TransformationAttestation,
    ) -> Self {
        let hash = compute_sha256_hash(module_bytes);
        self.inputs.push(InputArtifact {
            artifact: ArtifactDescriptor {
                name: name.into(),
                hash,
                size: module_bytes.len() as u64,
            },
            signature_status: SignatureStatus::Verified,
            signature_info: None,
            provenance: None,
            transformation_chain: Some(Box::new(prior_attestation)),
        });
        self
    }

    /// Build the attestation (without signing)
    ///
    /// Returns the attestation structure. The attestation_signature field
    /// will have algorithm="unsigned" and empty signature.
    pub fn build(self, output_bytes: &[u8], output_name: impl Into<String>) -> TransformationAttestation {
        let output_hash = compute_sha256_hash(output_bytes);
        let timestamp = chrono::Utc::now().to_rfc3339();
        let attestation_id = generate_uuid_v4();

        TransformationAttestation {
            version: "1.0".to_string(),
            transformation_type: self.transformation_type,
            attestation_id,
            timestamp: timestamp.clone(),
            output: ArtifactDescriptor {
                name: output_name.into(),
                hash: output_hash,
                size: output_bytes.len() as u64,
            },
            inputs: self.inputs,
            tool: ToolInfo {
                name: self.tool_name,
                version: self.tool_version,
                tool_hash: self.tool_hash,
                parameters: self.tool_parameters,
            },
            attestation_signature: AttestationSignature {
                algorithm: "unsigned".to_string(),
                signature: String::new(),
                key_id: None,
                signer_identity: None,
                signed_at: timestamp,
            },
            metadata: self.metadata,
        }
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Compute SHA-256 hash of bytes and return as hex string
fn compute_sha256_hash(bytes: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Generate a UUID v4 (random) for attestation IDs
fn generate_uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("getrandom failed");

    // Set version (4) and variant (RFC 4122)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u64::from_be_bytes([0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_basic() {
        let input = b"test input module";
        let output = b"test output module";

        let attestation = TransformationAttestationBuilder::new_optimization("loom", "0.1.0")
            .add_input_unsigned(input, "input.wasm")
            .add_parameter("opt_level", serde_json::json!("aggressive"))
            .build(output, "output.wasm");

        assert_eq!(attestation.version, "1.0");
        assert_eq!(attestation.transformation_type, TransformationType::Optimization);
        assert_eq!(attestation.tool.name, "loom");
        assert_eq!(attestation.tool.version, "0.1.0");
        assert_eq!(attestation.inputs.len(), 1);
        assert_eq!(attestation.inputs[0].signature_status, SignatureStatus::Unsigned);
    }

    #[test]
    fn test_json_roundtrip() {
        let input = b"test input";
        let output = b"test output";

        let attestation = TransformationAttestationBuilder::new_composition("wac", "0.5.0")
            .add_input_unsigned(input, "a.wasm")
            .build(output, "composed.wasm");

        let json = attestation.to_json().unwrap();
        let parsed = TransformationAttestation::from_json(&json).unwrap();

        assert_eq!(parsed.tool.name, "wac");
        assert_eq!(parsed.transformation_type, TransformationType::Composition);
    }

    #[test]
    fn test_section_names() {
        assert_eq!(TRANSFORMATION_ATTESTATION_SECTION, "wsc.transformation.attestation");
        assert_eq!(TRANSFORMATION_AUDIT_TRAIL_SECTION, "wsc.transformation.audit_trail");
    }
}
