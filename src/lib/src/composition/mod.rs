/// Component composition and provenance tracking
///
/// This module provides support for WebAssembly component composition with
/// full provenance tracking, enabling supply chain security and compliance
/// with SLSA, in-toto, and SBOM standards.
///
/// # Overview
///
/// When composing WASM components, it's critical to track:
/// - Where each component came from (source repository, commit)
/// - Who built it (builder identity, tool versions)
/// - How it was composed (composition tool, dependencies)
/// - Who verified/integrated it (integrator signatures)
///
/// This module provides the infrastructure to:
/// 1. Capture build provenance for individual components
/// 2. Track composition metadata during wac composition
/// 3. Generate SBOMs (Software Bill of Materials)
/// 4. Create in-toto attestations
/// 5. Verify full provenance chains
///
/// # Example: Basic Provenance Tracking
///
/// ```ignore
/// use wsc::composition::*;
///
/// // Capture build provenance for a component
/// let provenance = ProvenanceBuilder::new()
///     .component_name("my-component")
///     .version("1.0.0")
///     .source_repo("https://github.com/owner/my-component")
///     .commit_sha("abc123...")
///     .build_tool("cargo", "1.75.0")
///     .build();
///
/// // Embed in WASM as custom section
/// let with_provenance = embed_provenance(wasm_module, &provenance)?;
///
/// // Later: Extract and verify
/// let extracted = extract_provenance(&with_provenance)?;
/// assert_eq!(extracted.commit_sha, "abc123...");
/// ```
///
/// # Example: Composition Manifest
///
/// ```ignore
/// // Create composition manifest
/// let manifest = CompositionManifest {
///     version: "1.0".to_string(),
///     tool: "wac".to_string(),
///     tool_version: "0.5.0".to_string(),
///     components: vec![
///         ComponentRef {
///             id: "component-a".to_string(),
///             hash: compute_sha256(comp_a),
///             source: Some("https://github.com/owner/comp-a".to_string()),
///         },
///         ComponentRef {
///             id: "component-b".to_string(),
///             hash: compute_sha256(comp_b),
///             source: Some("https://github.com/owner/comp-b".to_string()),
///         },
///     ],
/// };
///
/// // Embed in composed WASM
/// let composed_with_manifest = embed_composition_manifest(composed, &manifest)?;
/// ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
            build_tool_version: self.build_tool_version.unwrap_or_else(|| "unknown".to_string()),
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

/// Reference to a component in a composition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentRef {
    /// Component identifier
    pub id: String,

    /// SHA-256 hash of the component
    pub hash: String,

    /// Source URL (repository, registry, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Signature index (which signature in the WASM covers this component)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_index: Option<usize>,
}

/// Composition manifest
///
/// Embedded in composed WASM as a custom section to track
/// how components were composed together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositionManifest {
    /// Manifest format version
    pub version: String,

    /// Composition tool name (e.g., "wac")
    pub tool: String,

    /// Composition tool version
    pub tool_version: String,

    /// Timestamp of composition (ISO 8601)
    pub timestamp: String,

    /// Components that were composed
    pub components: Vec<ComponentRef>,

    /// Integrator who signed the composed result
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrator: Option<IntegratorInfo>,

    /// Additional metadata
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub metadata: HashMap<String, String>,
}

/// Information about the integrator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegratorInfo {
    /// Integrator identity (certificate DN)
    pub identity: String,

    /// Signature index
    pub signature_index: usize,

    /// Verification timestamp
    pub verification_timestamp: String,
}

impl CompositionManifest {
    /// Create a new composition manifest
    pub fn new(tool: impl Into<String>, tool_version: impl Into<String>) -> Self {
        Self {
            version: "1.0".to_string(),
            tool: tool.into(),
            tool_version: tool_version.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            components: Vec::new(),
            integrator: None,
            metadata: HashMap::new(),
        }
    }

    /// Add a component reference
    pub fn add_component(&mut self, id: impl Into<String>, hash: impl Into<String>) {
        self.components.push(ComponentRef {
            id: id.into(),
            hash: hash.into(),
            source: None,
            signature_index: None,
        });
    }

    /// Add component with source info
    pub fn add_component_with_source(
        &mut self,
        id: impl Into<String>,
        hash: impl Into<String>,
        source: impl Into<String>,
    ) {
        self.components.push(ComponentRef {
            id: id.into(),
            hash: hash.into(),
            source: Some(source.into()),
            signature_index: None,
        });
    }

    /// Set integrator information
    pub fn set_integrator(&mut self, identity: impl Into<String>, signature_index: usize) {
        self.integrator = Some(IntegratorInfo {
            identity: identity.into(),
            signature_index,
            verification_timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Serialize to CBOR (compact binary format)
    #[cfg(feature = "cbor")]
    pub fn to_cbor(&self) -> Result<Vec<u8>, serde_cbor::Error> {
        serde_cbor::to_vec(self)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Deserialize from CBOR
    #[cfg(feature = "cbor")]
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, serde_cbor::Error> {
        serde_cbor::from_slice(bytes)
    }
}

/// Custom section name for composition manifest
pub const COMPOSITION_MANIFEST_SECTION: &str = "wsc.composition.manifest";

/// Custom section name for build provenance
pub const BUILD_PROVENANCE_SECTION: &str = "wsc.build.provenance";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provenance_builder() {
        let prov = ProvenanceBuilder::new()
            .component_name("test-component")
            .version("1.0.0")
            .source_repo("https://github.com/test/comp")
            .commit_sha("abc123")
            .build_tool("cargo", "1.75.0")
            .builder_identity("CI/CD")
            .add_metadata("platform", "wasm32-wasi")
            .build();

        assert_eq!(prov.name, "test-component");
        assert_eq!(prov.version, "1.0.0");
        assert_eq!(prov.source_repo, Some("https://github.com/test/comp".to_string()));
        assert_eq!(prov.commit_sha, Some("abc123".to_string()));
        assert_eq!(prov.build_tool, "cargo");
        assert_eq!(prov.metadata.get("platform"), Some(&"wasm32-wasi".to_string()));
    }

    #[test]
    fn test_composition_manifest() {
        let mut manifest = CompositionManifest::new("wac", "0.5.0");

        manifest.add_component("comp-a", "sha256:abc123");
        manifest.add_component_with_source(
            "comp-b",
            "sha256:def456",
            "https://github.com/test/comp-b",
        );

        manifest.set_integrator("CN=Integrator, O=Test Corp", 2);

        assert_eq!(manifest.components.len(), 2);
        assert_eq!(manifest.components[0].id, "comp-a");
        assert_eq!(manifest.components[1].source, Some("https://github.com/test/comp-b".to_string()));
        assert!(manifest.integrator.is_some());
    }

    #[test]
    fn test_manifest_json_roundtrip() {
        let mut manifest = CompositionManifest::new("wac", "0.5.0");
        manifest.add_component("test", "sha256:123");

        let json = manifest.to_json().unwrap();
        let deserialized = CompositionManifest::from_json(&json).unwrap();

        assert_eq!(deserialized.tool, "wac");
        assert_eq!(deserialized.components.len(), 1);
        assert_eq!(deserialized.components[0].id, "test");
    }
}
