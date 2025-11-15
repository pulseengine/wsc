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

/// Custom section name for SBOM
pub const SBOM_SECTION: &str = "wsc.sbom";

/// Custom section name for in-toto attestation
pub const INTOTO_ATTESTATION_SECTION: &str = "wsc.intoto.attestation";

// ============================================================================
// SBOM Generation (CycloneDX Format)
// ============================================================================

/// CycloneDX SBOM (Software Bill of Materials)
///
/// Follows the CycloneDX 1.5 specification for SBOM.
/// See: https://cyclonedx.org/specification/overview/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    /// BOM format (always "CycloneDX")
    #[serde(rename = "bomFormat")]
    pub bom_format: String,

    /// Spec version (e.g., "1.5")
    #[serde(rename = "specVersion")]
    pub spec_version: String,

    /// Serial number (UUID)
    #[serde(rename = "serialNumber")]
    pub serial_number: String,

    /// Version of this SBOM
    pub version: u32,

    /// Metadata about the SBOM
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<SbomMetadata>,

    /// Components in the SBOM
    pub components: Vec<SbomComponent>,

    /// Dependencies between components
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub dependencies: Vec<SbomDependency>,
}

/// SBOM metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomMetadata {
    /// Timestamp when SBOM was created
    pub timestamp: String,

    /// Tools used to create the SBOM
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tools: Vec<SbomTool>,

    /// Component being described (the composed WASM)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<SbomComponent>,
}

/// Tool that created the SBOM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomTool {
    /// Vendor of the tool
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,

    /// Tool name
    pub name: String,

    /// Tool version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Component in the SBOM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    /// Component type (e.g., "application", "library")
    #[serde(rename = "type")]
    pub component_type: String,

    /// Component name
    pub name: String,

    /// Component version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Unique identifier (e.g., purl)
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,

    /// Hashes of the component
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hashes: Vec<SbomHash>,

    /// External references
    #[serde(rename = "externalReferences", skip_serializing_if = "Vec::is_empty", default)]
    pub external_references: Vec<SbomExternalReference>,
}

/// Hash of a component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomHash {
    /// Hash algorithm (e.g., "SHA-256")
    pub alg: String,

    /// Hash value (hex encoded)
    pub content: String,
}

/// External reference to a component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomExternalReference {
    /// Reference type (e.g., "vcs", "distribution")
    #[serde(rename = "type")]
    pub ref_type: String,

    /// URL
    pub url: String,
}

/// Dependency relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDependency {
    /// Component reference
    #[serde(rename = "ref")]
    pub component_ref: String,

    /// Dependencies of this component
    #[serde(rename = "dependsOn", skip_serializing_if = "Vec::is_empty", default)]
    pub depends_on: Vec<String>,
}

impl Sbom {
    /// Create a new SBOM for a composed WASM component
    pub fn new(component_name: impl Into<String>, component_version: impl Into<String>) -> Self {
        use uuid::Uuid;

        let name = component_name.into();
        let component = SbomComponent {
            component_type: "application".to_string(),
            name: name.clone(),
            version: Some(component_version.into()),
            bom_ref: format!("pkg:wasm/{}", name),
            hashes: Vec::new(),
            external_references: Vec::new(),
        };

        Self {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
            version: 1,
            metadata: Some(SbomMetadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
                tools: vec![SbomTool {
                    vendor: Some("wsc".to_string()),
                    name: "wsc".to_string(),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                }],
                component: Some(component),
            }),
            components: Vec::new(),
            dependencies: Vec::new(),
        }
    }

    /// Add a component to the SBOM
    pub fn add_component(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
        hash: impl Into<String>,
    ) {
        let name_str = name.into();
        let component = SbomComponent {
            component_type: "library".to_string(),
            name: name_str.clone(),
            version: Some(version.into()),
            bom_ref: format!("pkg:wasm/{}", name_str),
            hashes: vec![SbomHash {
                alg: "SHA-256".to_string(),
                content: hash.into(),
            }],
            external_references: Vec::new(),
        };
        self.components.push(component);
    }

    /// Add a component with source repository
    pub fn add_component_with_source(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
        hash: impl Into<String>,
        source_repo: impl Into<String>,
    ) {
        let name_str = name.into();
        let component = SbomComponent {
            component_type: "library".to_string(),
            name: name_str.clone(),
            version: Some(version.into()),
            bom_ref: format!("pkg:wasm/{}", name_str),
            hashes: vec![SbomHash {
                alg: "SHA-256".to_string(),
                content: hash.into(),
            }],
            external_references: vec![SbomExternalReference {
                ref_type: "vcs".to_string(),
                url: source_repo.into(),
            }],
        };
        self.components.push(component);
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

// ============================================================================
// in-toto Attestation
// ============================================================================

/// in-toto attestation
///
/// Follows the in-toto attestation framework specification.
/// See: https://github.com/in-toto/attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoAttestation {
    /// Payload type (always "application/vnd.in-toto+json")
    #[serde(rename = "_type")]
    pub payload_type: String,

    /// Subject being attested
    pub subject: Vec<InTotoSubject>,

    /// Predicate type
    #[serde(rename = "predicateType")]
    pub predicate_type: String,

    /// Predicate (the actual attestation content)
    pub predicate: InTotoPredicate,
}

/// Subject of an in-toto attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoSubject {
    /// Name/identifier of the subject
    pub name: String,

    /// Digest of the subject
    pub digest: HashMap<String, String>,
}

/// Predicate for composition attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoPredicate {
    /// Builder information
    pub builder: InTotoBuilder,

    /// Build type
    #[serde(rename = "buildType")]
    pub build_type: String,

    /// Invocation details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocation: Option<InTotoInvocation>,

    /// Materials (input components)
    pub materials: Vec<InTotoMaterial>,

    /// Metadata
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Builder information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoBuilder {
    /// Builder identity
    pub id: String,
}

/// Invocation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoInvocation {
    /// Configuration source
    #[serde(rename = "configSource")]
    pub config_source: InTotoConfigSource,

    /// Parameters
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub parameters: HashMap<String, serde_json::Value>,

    /// Environment variables
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub environment: HashMap<String, String>,
}

/// Configuration source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoConfigSource {
    /// URI of the config
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// Digest of the config
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub digest: HashMap<String, String>,

    /// Entry point
    #[serde(rename = "entryPoint", skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<String>,
}

/// Material (input) to the build
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoMaterial {
    /// URI of the material
    pub uri: String,

    /// Digest of the material
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub digest: HashMap<String, String>,
}

impl InTotoAttestation {
    /// Create a new composition attestation
    pub fn new_composition(
        composed_name: impl Into<String>,
        composed_hash: impl Into<String>,
        builder_id: impl Into<String>,
    ) -> Self {
        let mut digest = HashMap::new();
        digest.insert("sha256".to_string(), composed_hash.into());

        Self {
            payload_type: "application/vnd.in-toto+json".to_string(),
            subject: vec![InTotoSubject {
                name: composed_name.into(),
                digest,
            }],
            predicate_type: "https://wsc.dev/in-toto/composition/v1".to_string(),
            predicate: InTotoPredicate {
                builder: InTotoBuilder {
                    id: builder_id.into(),
                },
                build_type: "https://wsc.dev/composition@v1".to_string(),
                invocation: None,
                materials: Vec::new(),
                metadata: HashMap::new(),
            },
        }
    }

    /// Add a material (input component)
    pub fn add_material(&mut self, uri: impl Into<String>, hash: impl Into<String>) {
        let mut digest = HashMap::new();
        digest.insert("sha256".to_string(), hash.into());

        self.predicate.materials.push(InTotoMaterial {
            uri: uri.into(),
            digest,
        });
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

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

    #[test]
    fn test_sbom_creation() {
        let sbom = Sbom::new("composed-app", "1.0.0");

        assert_eq!(sbom.bom_format, "CycloneDX");
        assert_eq!(sbom.spec_version, "1.5");
        assert!(sbom.serial_number.starts_with("urn:uuid:"));
        assert_eq!(sbom.version, 1);
        assert!(sbom.metadata.is_some());
    }

    #[test]
    fn test_sbom_add_components() {
        let mut sbom = Sbom::new("composed-app", "1.0.0");

        sbom.add_component("component-a", "1.0.0", "abc123");
        sbom.add_component_with_source(
            "component-b",
            "2.0.0",
            "def456",
            "https://github.com/test/component-b",
        );

        assert_eq!(sbom.components.len(), 2);
        assert_eq!(sbom.components[0].name, "component-a");
        assert_eq!(sbom.components[0].hashes[0].alg, "SHA-256");
        assert_eq!(sbom.components[0].hashes[0].content, "abc123");

        assert_eq!(sbom.components[1].name, "component-b");
        assert_eq!(sbom.components[1].external_references.len(), 1);
        assert_eq!(sbom.components[1].external_references[0].ref_type, "vcs");
    }

    #[test]
    fn test_sbom_json_serialization() {
        let mut sbom = Sbom::new("test-app", "1.0.0");
        sbom.add_component("comp-a", "1.0.0", "hash123");

        let json = sbom.to_json().unwrap();
        assert!(json.contains("CycloneDX"));
        assert!(json.contains("comp-a"));

        // Verify it's valid JSON and can be deserialized
        let deserialized = Sbom::from_json(&json).unwrap();
        assert_eq!(deserialized.components.len(), 1);
        assert_eq!(deserialized.components[0].name, "comp-a");
    }

    #[test]
    fn test_sbom_metadata() {
        let sbom = Sbom::new("test-app", "1.0.0");

        let metadata = sbom.metadata.as_ref().unwrap();
        assert!(!metadata.timestamp.is_empty());
        assert_eq!(metadata.tools.len(), 1);
        assert_eq!(metadata.tools[0].name, "wsc");
        assert!(metadata.tools[0].vendor.is_some());

        assert!(metadata.component.is_some());
        let component = metadata.component.as_ref().unwrap();
        assert_eq!(component.name, "test-app");
        assert_eq!(component.version.as_ref().unwrap(), "1.0.0");
    }

    #[test]
    fn test_intoto_attestation_creation() {
        let attestation = InTotoAttestation::new_composition(
            "composed.wasm",
            "abc123def456",
            "wsc-builder",
        );

        assert_eq!(attestation.payload_type, "application/vnd.in-toto+json");
        assert_eq!(attestation.subject.len(), 1);
        assert_eq!(attestation.subject[0].name, "composed.wasm");
        assert_eq!(attestation.subject[0].digest.get("sha256"), Some(&"abc123def456".to_string()));
        assert_eq!(attestation.predicate.builder.id, "wsc-builder");
    }

    #[test]
    fn test_intoto_add_materials() {
        let mut attestation = InTotoAttestation::new_composition(
            "composed.wasm",
            "abc123",
            "builder",
        );

        attestation.add_material("component-a.wasm", "hash-a");
        attestation.add_material("component-b.wasm", "hash-b");

        assert_eq!(attestation.predicate.materials.len(), 2);
        assert_eq!(attestation.predicate.materials[0].uri, "component-a.wasm");
        assert_eq!(
            attestation.predicate.materials[0].digest.get("sha256"),
            Some(&"hash-a".to_string())
        );
        assert_eq!(attestation.predicate.materials[1].uri, "component-b.wasm");
    }

    #[test]
    fn test_intoto_json_serialization() {
        let mut attestation = InTotoAttestation::new_composition(
            "test.wasm",
            "hash123",
            "test-builder",
        );
        attestation.add_material("input.wasm", "input-hash");

        let json = attestation.to_json().unwrap();
        assert!(json.contains("application/vnd.in-toto+json"));
        assert!(json.contains("test.wasm"));
        assert!(json.contains("test-builder"));

        // Verify deserialization
        let deserialized = InTotoAttestation::from_json(&json).unwrap();
        assert_eq!(deserialized.subject.len(), 1);
        assert_eq!(deserialized.predicate.materials.len(), 1);
    }

    #[test]
    fn test_full_composition_workflow() {
        // 1. Create composition manifest
        let mut manifest = CompositionManifest::new("wac", "0.5.0");
        manifest.add_component_with_source(
            "component-a",
            "sha256:abc123",
            "https://github.com/owner/component-a",
        );
        manifest.add_component_with_source(
            "component-b",
            "sha256:def456",
            "https://github.com/owner/component-b",
        );
        manifest.set_integrator("CN=Integrator, O=Test Corp", 2);

        // 2. Generate SBOM
        let mut sbom = Sbom::new("composed-app", "1.0.0");
        for component in &manifest.components {
            if let Some(source) = &component.source {
                sbom.add_component_with_source(
                    &component.id,
                    "1.0.0",
                    &component.hash,
                    source,
                );
            } else {
                sbom.add_component(&component.id, "1.0.0", &component.hash);
            }
        }

        // 3. Create in-toto attestation
        let mut attestation = InTotoAttestation::new_composition(
            "composed-app.wasm",
            "composed-hash-xyz",
            "wsc-integrator",
        );
        for component in &manifest.components {
            attestation.add_material(&format!("{}.wasm", component.id), &component.hash);
        }

        // Verify everything is consistent
        assert_eq!(manifest.components.len(), 2);
        assert_eq!(sbom.components.len(), 2);
        assert_eq!(attestation.predicate.materials.len(), 2);

        // Verify all can be serialized
        let _manifest_json = manifest.to_json().unwrap();
        let _sbom_json = sbom.to_json().unwrap();
        let _attestation_json = attestation.to_json().unwrap();
    }

    #[test]
    fn test_cyclonedx_spec_compliance() {
        let sbom = Sbom::new("test", "1.0.0");
        let json = sbom.to_json().unwrap();

        // Verify required CycloneDX 1.5 fields
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.5");
        assert!(parsed["serialNumber"].as_str().unwrap().starts_with("urn:uuid:"));
        assert_eq!(parsed["version"], 1);
        assert!(parsed["metadata"].is_object());
    }

    #[test]
    fn test_intoto_predicate_type() {
        let attestation = InTotoAttestation::new_composition("test", "hash", "builder");

        // Verify custom predicate type for composition
        assert_eq!(
            attestation.predicate_type,
            "https://wsc.dev/in-toto/composition/v1"
        );
        assert_eq!(
            attestation.predicate.build_type,
            "https://wsc.dev/composition@v1"
        );
    }
}
