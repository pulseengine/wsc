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
use crate::wasm_module::{Module, Section, CustomSection, SectionLike};
use crate::error::WSError;
use x509_parser::prelude::FromDer;

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
// Dependency Graph and Validation
// ============================================================================

/// Dependency graph for component composition
///
/// Tracks dependencies between components to enable:
/// - Cycle detection
/// - Substitution detection
/// - Dependency validation
#[derive(Debug, Clone)]
pub struct DependencyGraph {
    /// Map from component ID to its dependencies
    dependencies: HashMap<String, Vec<String>>,

    /// Map from component ID to its expected hash
    expected_hashes: HashMap<String, String>,

    /// Map from component ID to actual hash (for validation)
    actual_hashes: HashMap<String, String>,
}

impl DependencyGraph {
    /// Create a new empty dependency graph
    pub fn new() -> Self {
        Self {
            dependencies: HashMap::new(),
            expected_hashes: HashMap::new(),
            actual_hashes: HashMap::new(),
        }
    }

    /// Add a component with its expected hash
    pub fn add_component(&mut self, id: impl Into<String>, expected_hash: impl Into<String>) {
        let id = id.into();
        self.expected_hashes.insert(id.clone(), expected_hash.into());
        self.dependencies.entry(id).or_insert_with(Vec::new);
    }

    /// Add a dependency between two components
    pub fn add_dependency(&mut self, from: impl Into<String>, to: impl Into<String>) {
        let from = from.into();
        let to = to.into();
        self.dependencies.entry(from).or_insert_with(Vec::new).push(to);
    }

    /// Set the actual hash for a component (for validation)
    pub fn set_actual_hash(&mut self, id: impl Into<String>, actual_hash: impl Into<String>) {
        self.actual_hashes.insert(id.into(), actual_hash.into());
    }

    /// Build a dependency graph from a composition manifest
    pub fn from_manifest(manifest: &CompositionManifest) -> Self {
        let mut graph = Self::new();

        for component in &manifest.components {
            graph.add_component(&component.id, &component.hash);
        }

        graph
    }

    /// Detect cycles in the dependency graph using depth-first search
    ///
    /// Returns the first cycle found, if any.
    pub fn detect_cycles(&self) -> Option<Vec<String>> {
        let mut visited = HashMap::new();
        let mut rec_stack = HashMap::new();

        for node in self.dependencies.keys() {
            if !visited.contains_key(node) {
                if let Some(cycle) = self.dfs_cycle_detection(
                    node,
                    &mut visited,
                    &mut rec_stack,
                    &mut Vec::new(),
                ) {
                    return Some(cycle);
                }
            }
        }

        None
    }

    /// DFS helper for cycle detection
    fn dfs_cycle_detection(
        &self,
        node: &str,
        visited: &mut HashMap<String, bool>,
        rec_stack: &mut HashMap<String, bool>,
        path: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        visited.insert(node.to_string(), true);
        rec_stack.insert(node.to_string(), true);
        path.push(node.to_string());

        if let Some(neighbors) = self.dependencies.get(node) {
            for neighbor in neighbors {
                if !visited.contains_key(neighbor.as_str()) {
                    if let Some(cycle) = self.dfs_cycle_detection(
                        neighbor,
                        visited,
                        rec_stack,
                        path,
                    ) {
                        return Some(cycle);
                    }
                } else if *rec_stack.get(neighbor.as_str()).unwrap_or(&false) {
                    // Found a cycle - extract it from the path
                    let cycle_start = path.iter().position(|x| x == neighbor).unwrap();
                    let mut cycle = path[cycle_start..].to_vec();
                    cycle.push(neighbor.clone());
                    return Some(cycle);
                }
            }
        }

        rec_stack.insert(node.to_string(), false);
        path.pop();
        None
    }

    /// Detect component substitution by comparing expected vs actual hashes
    ///
    /// Returns a list of components that have been substituted.
    pub fn detect_substitutions(&self) -> Vec<ComponentSubstitution> {
        let mut substitutions = Vec::new();

        for (id, expected_hash) in &self.expected_hashes {
            if let Some(actual_hash) = self.actual_hashes.get(id) {
                if expected_hash != actual_hash {
                    substitutions.push(ComponentSubstitution {
                        component_id: id.clone(),
                        expected_hash: expected_hash.clone(),
                        actual_hash: actual_hash.clone(),
                    });
                }
            }
        }

        substitutions
    }

    /// Validate the dependency graph
    ///
    /// Returns an error if:
    /// - Cycles are detected
    /// - Component substitutions are detected
    /// - Components are missing
    pub fn validate(&self) -> Result<ValidationResult, ValidationError> {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        // Check for cycles
        if let Some(cycle) = self.detect_cycles() {
            errors.push(format!("Cycle detected: {}", cycle.join(" -> ")));
        }

        // Check for substitutions
        let substitutions = self.detect_substitutions();
        if !substitutions.is_empty() {
            for sub in &substitutions {
                errors.push(format!(
                    "Component '{}' substituted: expected hash '{}', actual hash '{}'",
                    sub.component_id, sub.expected_hash, sub.actual_hash
                ));
            }
        }

        // Check for missing components
        for (id, deps) in &self.dependencies {
            for dep in deps {
                if !self.dependencies.contains_key(dep) {
                    warnings.push(format!(
                        "Component '{}' depends on missing component '{}'",
                        id, dep
                    ));
                }
            }
        }

        Ok(ValidationResult {
            valid: errors.is_empty(),
            errors,
            warnings,
        })
    }

    /// Get all components in topological order (dependencies first)
    ///
    /// Returns None if there are cycles.
    pub fn topological_sort(&self) -> Option<Vec<String>> {
        // Check for cycles first
        if self.detect_cycles().is_some() {
            return None;
        }

        let mut result = Vec::new();
        let mut visited = HashMap::new();
        let mut temp_mark = HashMap::new();

        for node in self.dependencies.keys() {
            if !visited.contains_key(node) {
                self.topological_visit(node, &mut visited, &mut temp_mark, &mut result);
            }
        }

        // Don't reverse - topological_visit already gives us dependencies-first order
        Some(result)
    }

    /// Helper for topological sort
    fn topological_visit(
        &self,
        node: &str,
        visited: &mut HashMap<String, bool>,
        temp_mark: &mut HashMap<String, bool>,
        result: &mut Vec<String>,
    ) {
        if temp_mark.contains_key(node) {
            return; // Cycle detected (shouldn't happen if we checked first)
        }

        if !visited.contains_key(node) {
            temp_mark.insert(node.to_string(), true);

            if let Some(neighbors) = self.dependencies.get(node) {
                for neighbor in neighbors {
                    self.topological_visit(neighbor, visited, temp_mark, result);
                }
            }

            visited.insert(node.to_string(), true);
            temp_mark.remove(node);
            result.push(node.to_string());
        }
    }
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Component substitution detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentSubstitution {
    pub component_id: String,
    pub expected_hash: String,
    pub actual_hash: String,
}

/// Validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Validation error
#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidationError {
    #[error("Validation failed: {0}")]
    Failed(String),
}

// ============================================================================
// Phase 3: Advanced Validation
// ============================================================================

/// Version constraint for dependency validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionConstraint {
    /// Exact version required
    Exact(String),
    /// Minimum version (inclusive)
    Minimum(String),
    /// Maximum version (inclusive)
    Maximum(String),
    /// Range (min, max) both inclusive
    Range(String, String),
    /// Any version allowed
    Any,
}

impl VersionConstraint {
    /// Check if a version satisfies this constraint
    pub fn satisfies(&self, version: &str) -> bool {
        match self {
            VersionConstraint::Exact(required) => version == required,
            VersionConstraint::Minimum(min) => Self::compare_versions(version, min) >= 0,
            VersionConstraint::Maximum(max) => Self::compare_versions(version, max) <= 0,
            VersionConstraint::Range(min, max) => {
                Self::compare_versions(version, min) >= 0
                    && Self::compare_versions(version, max) <= 0
            }
            VersionConstraint::Any => true,
        }
    }

    /// Simple semantic version comparison (major.minor.patch)
    /// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    fn compare_versions(v1: &str, v2: &str) -> i32 {
        let parse_version = |v: &str| -> Vec<u32> {
            v.split('.')
                .filter_map(|s| s.parse::<u32>().ok())
                .collect()
        };

        let v1_parts = parse_version(v1);
        let v2_parts = parse_version(v2);

        for i in 0..v1_parts.len().max(v2_parts.len()) {
            let p1 = v1_parts.get(i).copied().unwrap_or(0);
            let p2 = v2_parts.get(i).copied().unwrap_or(0);

            if p1 < p2 {
                return -1;
            } else if p1 > p2 {
                return 1;
            }
        }

        0
    }
}

/// Version policy for component validation
#[derive(Debug, Clone)]
pub struct VersionPolicy {
    /// Map from component ID to version constraint
    constraints: HashMap<String, VersionConstraint>,
}

impl VersionPolicy {
    /// Create a new empty version policy
    pub fn new() -> Self {
        Self {
            constraints: HashMap::new(),
        }
    }

    /// Require an exact version for a component
    pub fn require_exact(&mut self, component_id: impl Into<String>, version: impl Into<String>) {
        self.constraints
            .insert(component_id.into(), VersionConstraint::Exact(version.into()));
    }

    /// Require a minimum version for a component
    pub fn require_minimum(&mut self, component_id: impl Into<String>, version: impl Into<String>) {
        self.constraints
            .insert(component_id.into(), VersionConstraint::Minimum(version.into()));
    }

    /// Require a maximum version for a component
    pub fn require_maximum(&mut self, component_id: impl Into<String>, version: impl Into<String>) {
        self.constraints
            .insert(component_id.into(), VersionConstraint::Maximum(version.into()));
    }

    /// Require a version range for a component
    pub fn require_range(
        &mut self,
        component_id: impl Into<String>,
        min_version: impl Into<String>,
        max_version: impl Into<String>,
    ) {
        self.constraints.insert(
            component_id.into(),
            VersionConstraint::Range(min_version.into(), max_version.into()),
        );
    }

    /// Validate a component version against policy
    pub fn validate_version(&self, component_id: &str, version: &str) -> Result<(), String> {
        if let Some(constraint) = self.constraints.get(component_id) {
            if constraint.satisfies(version) {
                Ok(())
            } else {
                Err(format!(
                    "Component '{}' version '{}' does not satisfy constraint {:?}",
                    component_id, version, constraint
                ))
            }
        } else {
            // No constraint for this component - allowed
            Ok(())
        }
    }
}

impl Default for VersionPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Source allow-list for dependency validation
#[derive(Debug, Clone)]
pub struct SourceAllowList {
    /// Allowed source URL patterns (exact match or prefix)
    allowed_sources: Vec<String>,
    /// Whether to allow components with no source specified
    allow_no_source: bool,
}

impl SourceAllowList {
    /// Create a new empty allow-list
    pub fn new() -> Self {
        Self {
            allowed_sources: Vec::new(),
            allow_no_source: false,
        }
    }

    /// Add an allowed source URL or prefix
    pub fn add_source(&mut self, source: impl Into<String>) {
        self.allowed_sources.push(source.into());
    }

    /// Allow components with no source specified
    pub fn allow_no_source(&mut self, allow: bool) {
        self.allow_no_source = allow;
    }

    /// Check if a source URL is allowed
    pub fn is_allowed(&self, source: Option<&str>) -> bool {
        match source {
            None => self.allow_no_source,
            Some(url) => self
                .allowed_sources
                .iter()
                .any(|allowed| url.starts_with(allowed) || url == allowed),
        }
    }

    /// Validate a component source against the allow-list
    pub fn validate_source(&self, component_id: &str, source: Option<&str>) -> Result<(), String> {
        if self.is_allowed(source) {
            Ok(())
        } else {
            Err(format!(
                "Component '{}' source '{}' is not in allow-list",
                component_id,
                source.unwrap_or("<no source>")
            ))
        }
    }
}

impl Default for SourceAllowList {
    fn default() -> Self {
        Self::new()
    }
}

/// Timestamp validation policy
///
/// Validates timestamps in provenance data to prevent:
/// - Time-based attacks (using old vulnerable versions)
/// - Timestamp manipulation to hide malicious activity
/// - Future-dated timestamps (clock skew attacks)
#[derive(Debug, Clone)]
pub struct TimestampPolicy {
    /// Maximum age for timestamps (in seconds from now)
    /// Signatures/compositions older than this are rejected
    max_age_seconds: Option<i64>,

    /// Maximum future tolerance (in seconds from now)
    /// Allows for clock skew between systems
    future_tolerance_seconds: i64,

    /// Require all timestamps to be present
    require_timestamps: bool,
}

impl TimestampPolicy {
    /// Create a new timestamp policy with default settings
    /// - No maximum age limit
    /// - 5 minutes future tolerance (for clock skew)
    /// - Timestamps required
    pub fn new() -> Self {
        Self {
            max_age_seconds: None,
            future_tolerance_seconds: 300, // 5 minutes
            require_timestamps: true,
        }
    }

    /// Set maximum age for timestamps
    /// Compositions/builds older than this are rejected
    pub fn with_max_age_seconds(mut self, seconds: i64) -> Self {
        self.max_age_seconds = Some(seconds);
        self
    }

    /// Set maximum age in days
    pub fn with_max_age_days(mut self, days: i64) -> Self {
        self.max_age_seconds = Some(days * 86400);
        self
    }

    /// Set future tolerance for clock skew
    pub fn with_future_tolerance_seconds(mut self, seconds: i64) -> Self {
        self.future_tolerance_seconds = seconds;
        self
    }

    /// Set whether timestamps are required
    pub fn require_timestamps(mut self, require: bool) -> Self {
        self.require_timestamps = require;
        self
    }

    /// Validate a timestamp string (ISO 8601 format)
    /// Returns Ok(()) if valid, Err(String) with reason if invalid
    pub fn validate_timestamp(&self, timestamp: &str, context: &str) -> Result<(), String> {
        // Parse the timestamp
        let parsed = chrono::DateTime::parse_from_rfc3339(timestamp)
            .map_err(|e| format!("Invalid timestamp format for {}: {}", context, e))?;

        let now = chrono::Utc::now();
        let timestamp_utc = parsed.with_timezone(&chrono::Utc);

        // Check if timestamp is too far in the future
        let future_limit = now + chrono::Duration::seconds(self.future_tolerance_seconds);
        if timestamp_utc > future_limit {
            return Err(format!(
                "{} timestamp is too far in the future (more than {} seconds ahead)",
                context, self.future_tolerance_seconds
            ));
        }

        // Check if timestamp is too old
        if let Some(max_age) = self.max_age_seconds {
            let age_limit = now - chrono::Duration::seconds(max_age);
            if timestamp_utc < age_limit {
                let age_days = max_age / 86400;
                return Err(format!(
                    "{} timestamp is too old (older than {} days)",
                    context, age_days
                ));
            }
        }

        Ok(())
    }

    /// Validate an optional timestamp
    pub fn validate_optional_timestamp(
        &self,
        timestamp: Option<&str>,
        context: &str,
    ) -> Result<(), String> {
        match timestamp {
            Some(ts) => self.validate_timestamp(ts, context),
            None => {
                if self.require_timestamps {
                    Err(format!("{} timestamp is required but missing", context))
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl Default for TimestampPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Validation mode configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    /// Lenient mode - warnings don't fail validation
    Lenient,
    /// Strict mode - warnings are treated as errors
    Strict,
}

/// Extended validation configuration
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Validation mode (lenient or strict)
    pub mode: ValidationMode,
    /// Version policy (optional)
    pub version_policy: Option<VersionPolicy>,
    /// Source allow-list (optional)
    pub source_allow_list: Option<SourceAllowList>,
    /// Timestamp validation policy (optional)
    pub timestamp_policy: Option<TimestampPolicy>,
    /// Enable transitive dependency validation
    pub validate_transitive: bool,
}

impl ValidationConfig {
    /// Create a new lenient validation config
    pub fn lenient() -> Self {
        Self {
            mode: ValidationMode::Lenient,
            version_policy: None,
            source_allow_list: None,
            timestamp_policy: None,
            validate_transitive: false,
        }
    }

    /// Create a new strict validation config
    pub fn strict() -> Self {
        Self {
            mode: ValidationMode::Strict,
            version_policy: None,
            source_allow_list: None,
            timestamp_policy: None,
            validate_transitive: false,
        }
    }

    /// Set version policy
    pub fn with_version_policy(mut self, policy: VersionPolicy) -> Self {
        self.version_policy = Some(policy);
        self
    }

    /// Set source allow-list
    pub fn with_source_allow_list(mut self, allow_list: SourceAllowList) -> Self {
        self.source_allow_list = Some(allow_list);
        self
    }

    /// Set timestamp validation policy
    pub fn with_timestamp_policy(mut self, policy: TimestampPolicy) -> Self {
        self.timestamp_policy = Some(policy);
        self
    }

    /// Enable transitive dependency validation
    pub fn with_transitive_validation(mut self, enable: bool) -> Self {
        self.validate_transitive = enable;
        self
    }
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self::lenient()
    }
}

// Extend DependencyGraph with advanced validation
impl DependencyGraph {
    /// Validate with configuration
    pub fn validate_with_config(
        &self,
        config: &ValidationConfig,
    ) -> Result<ValidationResult, ValidationError> {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        // Standard validation (cycles, substitutions, missing)
        let basic_result = self.validate()?;
        errors.extend(basic_result.errors);
        warnings.extend(basic_result.warnings);

        // In strict mode, convert warnings to errors
        if config.mode == ValidationMode::Strict && !warnings.is_empty() {
            for warning in &warnings {
                errors.push(format!("STRICT MODE: {}", warning));
            }
            warnings.clear();
        }

        // Version policy validation
        if let Some(policy) = &config.version_policy {
            for (component_id, _) in &self.expected_hashes {
                // Extract version from component metadata (would need to be stored)
                // For now, we'll add a placeholder for version validation
                // This would integrate with the ComponentRef which already has version info
            }
        }

        // Source allow-list validation
        if let Some(_allow_list) = &config.source_allow_list {
            // Would validate component sources against allow-list
            // This would integrate with ComponentRef.source field
        }

        Ok(ValidationResult {
            valid: errors.is_empty(),
            errors,
            warnings,
        })
    }
}

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

// ============================================================================
// WASM Module Embedding/Extraction
// ============================================================================

/// Embed a composition manifest in a WASM module as a custom section
pub fn embed_composition_manifest(mut module: Module, manifest: &CompositionManifest) -> Result<Module, WSError> {
    let json = manifest.to_json().map_err(|e| {
        WSError::InternalError(format!("Failed to serialize composition manifest: {}", e))
    })?;

    let custom_section = CustomSection::new(
        COMPOSITION_MANIFEST_SECTION.to_string(),
        json.as_bytes().to_vec(),
    );

    module.sections.push(Section::Custom(custom_section));
    Ok(module)
}

/// Extract a composition manifest from a WASM module
pub fn extract_composition_manifest(module: &Module) -> Result<Option<CompositionManifest>, WSError> {
    for section in &module.sections {
        if let Section::Custom(custom) = section {
            if custom.name() == COMPOSITION_MANIFEST_SECTION {
                let json = std::str::from_utf8(custom.payload()).map_err(|e| {
                    WSError::InternalError(format!("Invalid UTF-8 in composition manifest: {}", e))
                })?;

                let manifest = CompositionManifest::from_json(json).map_err(|e| {
                    WSError::InternalError(format!("Failed to deserialize composition manifest: {}", e))
                })?;

                return Ok(Some(manifest));
            }
        }
    }
    Ok(None)
}

/// Embed a build provenance in a WASM module as a custom section
pub fn embed_build_provenance(mut module: Module, provenance: &BuildProvenance) -> Result<Module, WSError> {
    let json = serde_json::to_string_pretty(provenance).map_err(|e| {
        WSError::InternalError(format!("Failed to serialize build provenance: {}", e))
    })?;

    let custom_section = CustomSection::new(
        BUILD_PROVENANCE_SECTION.to_string(),
        json.as_bytes().to_vec(),
    );

    module.sections.push(Section::Custom(custom_section));
    Ok(module)
}

/// Extract build provenance from a WASM module
pub fn extract_build_provenance(module: &Module) -> Result<Option<BuildProvenance>, WSError> {
    for section in &module.sections {
        if let Section::Custom(custom) = section {
            if custom.name() == BUILD_PROVENANCE_SECTION {
                let json = std::str::from_utf8(custom.payload()).map_err(|e| {
                    WSError::InternalError(format!("Invalid UTF-8 in build provenance: {}", e))
                })?;

                let provenance = serde_json::from_str(json).map_err(|e| {
                    WSError::InternalError(format!("Failed to deserialize build provenance: {}", e))
                })?;

                return Ok(Some(provenance));
            }
        }
    }
    Ok(None)
}

/// Embed an SBOM in a WASM module as a custom section
pub fn embed_sbom(mut module: Module, sbom: &Sbom) -> Result<Module, WSError> {
    let json = sbom.to_json().map_err(|e| {
        WSError::InternalError(format!("Failed to serialize SBOM: {}", e))
    })?;

    let custom_section = CustomSection::new(
        SBOM_SECTION.to_string(),
        json.as_bytes().to_vec(),
    );

    module.sections.push(Section::Custom(custom_section));
    Ok(module)
}

/// Extract an SBOM from a WASM module
pub fn extract_sbom(module: &Module) -> Result<Option<Sbom>, WSError> {
    for section in &module.sections {
        if let Section::Custom(custom) = section {
            if custom.name() == SBOM_SECTION {
                let json = std::str::from_utf8(custom.payload()).map_err(|e| {
                    WSError::InternalError(format!("Invalid UTF-8 in SBOM: {}", e))
                })?;

                let sbom = Sbom::from_json(json).map_err(|e| {
                    WSError::InternalError(format!("Failed to deserialize SBOM: {}", e))
                })?;

                return Ok(Some(sbom));
            }
        }
    }
    Ok(None)
}

/// Embed an in-toto attestation in a WASM module as a custom section
pub fn embed_intoto_attestation(mut module: Module, attestation: &InTotoAttestation) -> Result<Module, WSError> {
    let json = attestation.to_json().map_err(|e| {
        WSError::InternalError(format!("Failed to serialize in-toto attestation: {}", e))
    })?;

    let custom_section = CustomSection::new(
        INTOTO_ATTESTATION_SECTION.to_string(),
        json.as_bytes().to_vec(),
    );

    module.sections.push(Section::Custom(custom_section));
    Ok(module)
}

/// Extract an in-toto attestation from a WASM module
pub fn extract_intoto_attestation(module: &Module) -> Result<Option<InTotoAttestation>, WSError> {
    for section in &module.sections {
        if let Section::Custom(custom) = section {
            if custom.name() == INTOTO_ATTESTATION_SECTION {
                let json = std::str::from_utf8(custom.payload()).map_err(|e| {
                    WSError::InternalError(format!("Invalid UTF-8 in in-toto attestation: {}", e))
                })?;

                let attestation = InTotoAttestation::from_json(json).map_err(|e| {
                    WSError::InternalError(format!("Failed to deserialize in-toto attestation: {}", e))
                })?;

                return Ok(Some(attestation));
            }
        }
    }
    Ok(None)
}

/// Embed all provenance data in a WASM module
///
/// This is a convenience function that embeds all four types of provenance
/// data in a single operation.
pub fn embed_all_provenance(
    module: Module,
    manifest: &CompositionManifest,
    provenance: &BuildProvenance,
    sbom: &Sbom,
    attestation: &InTotoAttestation,
) -> Result<Module, WSError> {
    let module = embed_composition_manifest(module, manifest)?;
    let module = embed_build_provenance(module, provenance)?;
    let module = embed_sbom(module, sbom)?;
    let module = embed_intoto_attestation(module, attestation)?;
    Ok(module)
}

/// Extract all provenance data from a WASM module
///
/// Returns a tuple of (manifest, provenance, sbom, attestation).
/// Any component that is not found will be None.
pub fn extract_all_provenance(
    module: &Module,
) -> Result<(
    Option<CompositionManifest>,
    Option<BuildProvenance>,
    Option<Sbom>,
    Option<InTotoAttestation>,
), WSError> {
    let manifest = extract_composition_manifest(module)?;
    let provenance = extract_build_provenance(module)?;
    let sbom = extract_sbom(module)?;
    let attestation = extract_intoto_attestation(module)?;
    Ok((manifest, provenance, sbom, attestation))
}

// ============================================================================
// Timestamp Validation Functions
// ============================================================================

/// Validate timestamps in a composition manifest
pub fn validate_manifest_timestamps(
    manifest: &CompositionManifest,
    policy: &TimestampPolicy,
) -> Result<(), String> {
    // Validate composition timestamp
    policy.validate_timestamp(&manifest.timestamp, "Composition")?;

    // Validate integrator timestamp if present
    if let Some(integrator) = &manifest.integrator {
        policy.validate_timestamp(&integrator.verification_timestamp, "Integrator verification")?;
    }

    Ok(())
}

/// Validate timestamps in build provenance
pub fn validate_provenance_timestamps(
    provenance: &BuildProvenance,
    policy: &TimestampPolicy,
) -> Result<(), String> {
    policy.validate_timestamp(&provenance.build_timestamp, "Build")?;
    Ok(())
}

/// Validate timestamps in an in-toto attestation
pub fn validate_attestation_timestamps(
    attestation: &InTotoAttestation,
    policy: &TimestampPolicy,
) -> Result<(), String> {
    // Validate metadata timestamps
    if let Some(finished_on_value) = attestation.predicate.metadata.get("finishedOn") {
        if let Some(finished_on) = finished_on_value.as_str() {
            policy.validate_timestamp(finished_on, "Build completion")?;
        }
    }

    Ok(())
}

/// Validate all timestamps in a WASM module's provenance data
pub fn validate_all_timestamps(
    module: &Module,
    policy: &TimestampPolicy,
) -> Result<ValidationResult, WSError> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    // Extract all provenance data
    let (manifest, provenance, _sbom, attestation) = extract_all_provenance(module)?;

    // Validate manifest timestamps
    if let Some(ref m) = manifest {
        if let Err(e) = validate_manifest_timestamps(m, policy) {
            errors.push(e);
        }
    } else if policy.require_timestamps {
        warnings.push("No composition manifest found for timestamp validation".to_string());
    }

    // Validate build provenance timestamps
    if let Some(ref p) = provenance {
        if let Err(e) = validate_provenance_timestamps(p, policy) {
            errors.push(e);
        }
    }

    // Validate attestation timestamps
    if let Some(ref a) = attestation {
        if let Err(e) = validate_attestation_timestamps(a, policy) {
            errors.push(e);
        }
    }

    Ok(ValidationResult {
        valid: errors.is_empty(),
        errors,
        warnings,
    })
}

/// Signature freshness validator
///
/// Validates that signatures were created within an acceptable time window
#[derive(Debug, Clone)]
pub struct SignatureFreshnessPolicy {
    /// Maximum age for signatures (in seconds)
    max_signature_age_seconds: Option<i64>,

    /// Minimum acceptable signature timestamp (absolute time)
    /// Useful for enforcing "no signatures before this date" policies
    minimum_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

impl SignatureFreshnessPolicy {
    /// Create a new signature freshness policy with no restrictions
    pub fn new() -> Self {
        Self {
            max_signature_age_seconds: None,
            minimum_timestamp: None,
        }
    }

    /// Set maximum signature age in seconds
    pub fn with_max_age_seconds(mut self, seconds: i64) -> Self {
        self.max_signature_age_seconds = Some(seconds);
        self
    }

    /// Set maximum signature age in days
    pub fn with_max_age_days(mut self, days: i64) -> Self {
        self.max_signature_age_seconds = Some(days * 86400);
        self
    }

    /// Set minimum acceptable timestamp
    /// Signatures created before this time are rejected
    pub fn with_minimum_timestamp(mut self, timestamp: chrono::DateTime<chrono::Utc>) -> Self {
        self.minimum_timestamp = Some(timestamp);
        self
    }

    /// Validate a signature timestamp
    pub fn validate(&self, timestamp: &str, context: &str) -> Result<(), String> {
        let parsed = chrono::DateTime::parse_from_rfc3339(timestamp)
            .map_err(|e| format!("Invalid timestamp format for {}: {}", context, e))?;

        let timestamp_utc = parsed.with_timezone(&chrono::Utc);
        let now = chrono::Utc::now();

        // Check maximum age
        if let Some(max_age) = self.max_signature_age_seconds {
            let age = now.signed_duration_since(timestamp_utc);
            if age.num_seconds() > max_age {
                let age_days = max_age / 86400;
                return Err(format!(
                    "{} signature is too old (created {} days ago, max age: {} days)",
                    context,
                    age.num_days(),
                    age_days
                ));
            }
        }

        // Check minimum timestamp
        if let Some(min_ts) = &self.minimum_timestamp {
            if timestamp_utc < *min_ts {
                return Err(format!(
                    "{} signature was created before minimum acceptable time ({})",
                    context,
                    min_ts.to_rfc3339()
                ));
            }
        }

        Ok(())
    }
}

impl Default for SignatureFreshnessPolicy {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Certificate Expiration Validation
// ============================================================================

/// Certificate validity policy
///
/// Validates X.509 certificates to ensure they are:
/// - Not expired
/// - Not used before their validity start date
/// - Have sufficient remaining validity
#[derive(Debug, Clone)]
pub struct CertificateValidityPolicy {
    /// Require minimum remaining validity (in seconds)
    /// Certificates expiring within this window are rejected
    min_remaining_validity_seconds: Option<i64>,

    /// Allow certificates not yet valid (for testing)
    allow_not_yet_valid: bool,
}

impl CertificateValidityPolicy {
    /// Create a new certificate validity policy with default settings
    /// - No minimum remaining validity requirement
    /// - Do not allow certificates not yet valid
    pub fn new() -> Self {
        Self {
            min_remaining_validity_seconds: None,
            allow_not_yet_valid: false,
        }
    }

    /// Set minimum remaining validity in seconds
    /// Certificates expiring within this time window are rejected
    pub fn with_min_remaining_validity_seconds(mut self, seconds: i64) -> Self {
        self.min_remaining_validity_seconds = Some(seconds);
        self
    }

    /// Set minimum remaining validity in days
    pub fn with_min_remaining_validity_days(mut self, days: i64) -> Self {
        self.min_remaining_validity_seconds = Some(days * 86400);
        self
    }

    /// Allow certificates that are not yet valid
    /// Useful for testing with future-dated certificates
    pub fn allow_not_yet_valid(mut self, allow: bool) -> Self {
        self.allow_not_yet_valid = allow;
        self
    }

    /// Validate certificate validity period using parsed not_before/not_after
    ///
    /// # Arguments
    /// * `not_before` - Certificate validity start time (ISO 8601)
    /// * `not_after` - Certificate validity end time (ISO 8601)
    /// * `context` - Description of the certificate for error messages
    pub fn validate_certificate_times(
        &self,
        not_before: &str,
        not_after: &str,
        context: &str,
    ) -> Result<(), String> {
        let now = chrono::Utc::now();

        // Parse timestamps
        let not_before_time = chrono::DateTime::parse_from_rfc3339(not_before)
            .map_err(|e| format!("Invalid not_before timestamp for {}: {}", context, e))?
            .with_timezone(&chrono::Utc);

        let not_after_time = chrono::DateTime::parse_from_rfc3339(not_after)
            .map_err(|e| format!("Invalid not_after timestamp for {}: {}", context, e))?
            .with_timezone(&chrono::Utc);

        // Check if certificate is not yet valid
        if now < not_before_time {
            if !self.allow_not_yet_valid {
                return Err(format!(
                    "{} certificate is not yet valid (valid from: {})",
                    context,
                    not_before_time.to_rfc3339()
                ));
            }
        }

        // Check if certificate is expired
        if now > not_after_time {
            return Err(format!(
                "{} certificate has expired (expired on: {})",
                context,
                not_after_time.to_rfc3339()
            ));
        }

        // Check minimum remaining validity
        if let Some(min_remaining) = self.min_remaining_validity_seconds {
            let remaining = not_after_time.signed_duration_since(now);
            if remaining.num_seconds() < min_remaining {
                let remaining_days = remaining.num_days();
                let min_days = min_remaining / 86400;
                return Err(format!(
                    "{} certificate expires too soon (remaining: {} days, minimum required: {} days)",
                    context, remaining_days, min_days
                ));
            }
        }

        Ok(())
    }

    /// Validate a certificate in DER format
    ///
    /// This function parses a DER-encoded X.509 certificate and validates
    /// its validity period.
    pub fn validate_certificate_der(
        &self,
        cert_der: &[u8],
        context: &str,
    ) -> Result<(), String> {
        // Parse the certificate using x509_parser
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
            .map_err(|e| format!("Failed to parse {} certificate: {:?}", context, e))?;

        // Get validity period
        let not_before = cert.validity().not_before;
        let not_after = cert.validity().not_after;

        // Convert to chrono DateTime for easier comparison
        let not_before_chrono = chrono::DateTime::<chrono::Utc>::from_timestamp(
            not_before.timestamp(),
            0,
        ).ok_or_else(|| format!("Invalid not_before timestamp for {}", context))?;

        let not_after_chrono = chrono::DateTime::<chrono::Utc>::from_timestamp(
            not_after.timestamp(),
            0,
        ).ok_or_else(|| format!("Invalid not_after timestamp for {}", context))?;

        // Validate using our policy
        self.validate_certificate_times(
            &not_before_chrono.to_rfc3339(),
            &not_after_chrono.to_rfc3339(),
            context,
        )
    }

    /// Validate a certificate in PEM format
    pub fn validate_certificate_pem(
        &self,
        cert_pem: &str,
        context: &str,
    ) -> Result<(), String> {
        // Parse PEM to get DER
        let pem = pem::parse(cert_pem)
            .map_err(|e| format!("Failed to parse {} PEM certificate: {}", context, e))?;

        self.validate_certificate_der(&pem.contents(), context)
    }
}

impl Default for CertificateValidityPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm_module::Module;

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

    // Helper to create a minimal WASM module for testing
    fn create_test_module() -> Module {
        Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![],
        }
    }

    #[test]
    fn test_embed_extract_composition_manifest() {
        let mut manifest = CompositionManifest::new("wac", "0.5.0");
        manifest.add_component("comp-a", "hash-a");
        manifest.add_component("comp-b", "hash-b");

        let module = create_test_module();
        let module_with_manifest = embed_composition_manifest(module, &manifest).unwrap();

        // Verify custom section was added
        assert_eq!(module_with_manifest.sections.len(), 1);

        // Extract and verify
        let extracted = extract_composition_manifest(&module_with_manifest).unwrap();
        assert!(extracted.is_some());

        let extracted_manifest = extracted.unwrap();
        assert_eq!(extracted_manifest.tool, "wac");
        assert_eq!(extracted_manifest.components.len(), 2);
        assert_eq!(extracted_manifest.components[0].id, "comp-a");
    }

    #[test]
    fn test_embed_extract_build_provenance() {
        let provenance = ProvenanceBuilder::new()
            .component_name("test-comp")
            .version("1.0.0")
            .source_repo("https://github.com/test/repo")
            .commit_sha("abc123")
            .build_tool("cargo", "1.75.0")
            .build();

        let module = create_test_module();
        let module_with_prov = embed_build_provenance(module, &provenance).unwrap();

        // Extract and verify
        let extracted = extract_build_provenance(&module_with_prov).unwrap();
        assert!(extracted.is_some());

        let extracted_prov = extracted.unwrap();
        assert_eq!(extracted_prov.name, "test-comp");
        assert_eq!(extracted_prov.version, "1.0.0");
        assert_eq!(extracted_prov.commit_sha, Some("abc123".to_string()));
    }

    #[test]
    fn test_embed_extract_sbom() {
        let mut sbom = Sbom::new("app", "1.0.0");
        sbom.add_component("comp-a", "1.0.0", "hash-a");
        sbom.add_component_with_source("comp-b", "2.0.0", "hash-b", "https://github.com/test/b");

        let module = create_test_module();
        let module_with_sbom = embed_sbom(module, &sbom).unwrap();

        // Extract and verify
        let extracted = extract_sbom(&module_with_sbom).unwrap();
        assert!(extracted.is_some());

        let extracted_sbom = extracted.unwrap();
        assert_eq!(extracted_sbom.components.len(), 2);
        assert_eq!(extracted_sbom.components[0].name, "comp-a");
        assert_eq!(extracted_sbom.components[1].name, "comp-b");
    }

    #[test]
    fn test_embed_extract_intoto_attestation() {
        let mut attestation = InTotoAttestation::new_composition(
            "app.wasm",
            "final-hash",
            "integrator",
        );
        attestation.add_material("comp-a.wasm", "hash-a");
        attestation.add_material("comp-b.wasm", "hash-b");

        let module = create_test_module();
        let module_with_att = embed_intoto_attestation(module, &attestation).unwrap();

        // Extract and verify
        let extracted = extract_intoto_attestation(&module_with_att).unwrap();
        assert!(extracted.is_some());

        let extracted_att = extracted.unwrap();
        assert_eq!(extracted_att.subject.len(), 1);
        assert_eq!(extracted_att.subject[0].name, "app.wasm");
        assert_eq!(extracted_att.predicate.materials.len(), 2);
    }

    #[test]
    fn test_embed_all_provenance() {
        let manifest = CompositionManifest::new("wac", "0.5.0");
        let provenance = ProvenanceBuilder::new()
            .component_name("app")
            .version("1.0.0")
            .build();
        let sbom = Sbom::new("app", "1.0.0");
        let attestation = InTotoAttestation::new_composition("app.wasm", "hash", "builder");

        let module = create_test_module();
        let module_with_all = embed_all_provenance(
            module,
            &manifest,
            &provenance,
            &sbom,
            &attestation,
        ).unwrap();

        // Should have 4 custom sections
        assert_eq!(module_with_all.sections.len(), 4);

        // Extract all and verify
        let (m, p, s, a) = extract_all_provenance(&module_with_all).unwrap();
        assert!(m.is_some());
        assert!(p.is_some());
        assert!(s.is_some());
        assert!(a.is_some());
    }

    #[test]
    fn test_extract_from_module_without_provenance() {
        let module = create_test_module();

        // Extracting from empty module should return None for all
        let manifest = extract_composition_manifest(&module).unwrap();
        assert!(manifest.is_none());

        let provenance = extract_build_provenance(&module).unwrap();
        assert!(provenance.is_none());

        let sbom = extract_sbom(&module).unwrap();
        assert!(sbom.is_none());

        let attestation = extract_intoto_attestation(&module).unwrap();
        assert!(attestation.is_none());
    }

    #[test]
    fn test_roundtrip_serialization() {
        // Create full provenance
        let manifest = CompositionManifest::new("wac", "0.5.0");
        let provenance = ProvenanceBuilder::new()
            .component_name("app")
            .version("1.0.0")
            .build();
        let sbom = Sbom::new("app", "1.0.0");
        let attestation = InTotoAttestation::new_composition("app.wasm", "hash", "builder");

        // Embed in module
        let module = create_test_module();
        let module_with_all = embed_all_provenance(
            module,
            &manifest,
            &provenance,
            &sbom,
            &attestation,
        ).unwrap();

        // Serialize to bytes
        let mut buffer = Vec::new();
        module_with_all.serialize(&mut buffer).unwrap();

        // Deserialize back
        let mut reader = std::io::Cursor::new(buffer);
        let deserialized_module = Module::deserialize(&mut reader).unwrap();

        // Extract and verify
        let (m, p, s, a) = extract_all_provenance(&deserialized_module).unwrap();
        assert!(m.is_some());
        assert!(p.is_some());
        assert!(s.is_some());
        assert!(a.is_some());

        // Verify data integrity
        assert_eq!(m.unwrap().tool, "wac");
        assert_eq!(p.unwrap().name, "app");
        assert_eq!(s.unwrap().bom_format, "CycloneDX");
        assert_eq!(a.unwrap().predicate.builder.id, "builder");
    }

    #[test]
    fn test_multiple_sections_preserved() {
        // Start with a module that has existing custom sections
        let mut module = create_test_module();
        let existing_section = CustomSection::new("existing".to_string(), vec![1, 2, 3]);
        module.sections.push(Section::Custom(existing_section));

        // Add provenance
        let manifest = CompositionManifest::new("wac", "0.5.0");
        let module_with_prov = embed_composition_manifest(module, &manifest).unwrap();

        // Should have both sections
        assert_eq!(module_with_prov.sections.len(), 2);

        // Verify both sections exist
        let mut found_existing = false;
        let mut found_manifest = false;

        for section in &module_with_prov.sections {
            if let Section::Custom(custom) = section {
                if custom.name() == "existing" {
                    found_existing = true;
                }
                if custom.name() == COMPOSITION_MANIFEST_SECTION {
                    found_manifest = true;
                }
            }
        }

        assert!(found_existing, "Existing section was lost");
        assert!(found_manifest, "Manifest section was not added");
    }

    // ========================================================================
    // Dependency Graph Tests
    // ========================================================================

    #[test]
    fn test_dependency_graph_creation() {
        let mut graph = DependencyGraph::new();
        graph.add_component("comp-a", "hash-a");
        graph.add_component("comp-b", "hash-b");

        // Graph should have two components
        assert_eq!(graph.expected_hashes.len(), 2);
    }

    #[test]
    fn test_dependency_graph_from_manifest() {
        let mut manifest = CompositionManifest::new("wac", "0.5.0");
        manifest.add_component("comp-a", "hash-a");
        manifest.add_component("comp-b", "hash-b");
        manifest.add_component("comp-c", "hash-c");

        let graph = DependencyGraph::from_manifest(&manifest);

        assert_eq!(graph.expected_hashes.len(), 3);
        assert_eq!(graph.expected_hashes.get("comp-a"), Some(&"hash-a".to_string()));
    }

    #[test]
    fn test_cycle_detection_no_cycle() {
        let mut graph = DependencyGraph::new();
        graph.add_component("a", "hash-a");
        graph.add_component("b", "hash-b");
        graph.add_component("c", "hash-c");

        // a -> b -> c (no cycle)
        graph.add_dependency("a", "b");
        graph.add_dependency("b", "c");

        let cycle = graph.detect_cycles();
        assert!(cycle.is_none(), "No cycle should be detected");
    }

    #[test]
    fn test_cycle_detection_simple_cycle() {
        let mut graph = DependencyGraph::new();
        graph.add_component("a", "hash-a");
        graph.add_component("b", "hash-b");

        // a -> b -> a (simple cycle)
        graph.add_dependency("a", "b");
        graph.add_dependency("b", "a");

        let cycle = graph.detect_cycles();
        assert!(cycle.is_some(), "Cycle should be detected");

        let cycle = cycle.unwrap();
        assert!(cycle.len() >= 2, "Cycle should have at least 2 nodes");
        assert!(cycle.contains(&"a".to_string()));
        assert!(cycle.contains(&"b".to_string()));
    }

    #[test]
    fn test_cycle_detection_complex_cycle() {
        let mut graph = DependencyGraph::new();
        graph.add_component("a", "hash-a");
        graph.add_component("b", "hash-b");
        graph.add_component("c", "hash-c");
        graph.add_component("d", "hash-d");

        // a -> b -> c -> d -> b (cycle involving b, c, d)
        graph.add_dependency("a", "b");
        graph.add_dependency("b", "c");
        graph.add_dependency("c", "d");
        graph.add_dependency("d", "b");

        let cycle = graph.detect_cycles();
        assert!(cycle.is_some(), "Cycle should be detected");

        let cycle = cycle.unwrap();
        // The cycle should be b -> c -> d -> b
        assert!(cycle.contains(&"b".to_string()));
        assert!(cycle.contains(&"c".to_string()));
        assert!(cycle.contains(&"d".to_string()));
    }

    #[test]
    fn test_substitution_detection_no_substitution() {
        let mut graph = DependencyGraph::new();
        graph.add_component("comp-a", "hash-a");
        graph.add_component("comp-b", "hash-b");

        // Set actual hashes that match expected
        graph.set_actual_hash("comp-a", "hash-a");
        graph.set_actual_hash("comp-b", "hash-b");

        let substitutions = graph.detect_substitutions();
        assert!(substitutions.is_empty(), "No substitutions should be detected");
    }

    #[test]
    fn test_substitution_detection_with_substitution() {
        let mut graph = DependencyGraph::new();
        graph.add_component("comp-a", "hash-a");
        graph.add_component("comp-b", "hash-b");

        // Set actual hash for comp-a that doesn't match expected
        graph.set_actual_hash("comp-a", "hash-a-modified");
        graph.set_actual_hash("comp-b", "hash-b");

        let substitutions = graph.detect_substitutions();
        assert_eq!(substitutions.len(), 1, "One substitution should be detected");

        let sub = &substitutions[0];
        assert_eq!(sub.component_id, "comp-a");
        assert_eq!(sub.expected_hash, "hash-a");
        assert_eq!(sub.actual_hash, "hash-a-modified");
    }

    #[test]
    fn test_substitution_detection_multiple() {
        let mut graph = DependencyGraph::new();
        graph.add_component("comp-a", "hash-a");
        graph.add_component("comp-b", "hash-b");
        graph.add_component("comp-c", "hash-c");

        // Two components have been substituted
        graph.set_actual_hash("comp-a", "hash-a-wrong");
        graph.set_actual_hash("comp-b", "hash-b");
        graph.set_actual_hash("comp-c", "hash-c-wrong");

        let substitutions = graph.detect_substitutions();
        assert_eq!(substitutions.len(), 2, "Two substitutions should be detected");
    }

    #[test]
    fn test_validation_success() {
        let mut graph = DependencyGraph::new();
        graph.add_component("comp-a", "hash-a");
        graph.add_component("comp-b", "hash-b");
        graph.add_dependency("comp-a", "comp-b");

        // Set matching actual hashes
        graph.set_actual_hash("comp-a", "hash-a");
        graph.set_actual_hash("comp-b", "hash-b");

        let result = graph.validate().unwrap();
        assert!(result.valid, "Validation should pass");
        assert!(result.errors.is_empty(), "No errors should be present");
    }

    #[test]
    fn test_validation_cycle_error() {
        let mut graph = DependencyGraph::new();
        graph.add_component("comp-a", "hash-a");
        graph.add_component("comp-b", "hash-b");

        // Create a cycle
        graph.add_dependency("comp-a", "comp-b");
        graph.add_dependency("comp-b", "comp-a");

        let result = graph.validate().unwrap();
        assert!(!result.valid, "Validation should fail due to cycle");
        assert!(!result.errors.is_empty(), "Errors should be present");
        assert!(result.errors[0].contains("Cycle detected"));
    }

    #[test]
    fn test_validation_substitution_error() {
        let mut graph = DependencyGraph::new();
        graph.add_component("comp-a", "hash-a");

        // Set wrong actual hash
        graph.set_actual_hash("comp-a", "hash-wrong");

        let result = graph.validate().unwrap();
        assert!(!result.valid, "Validation should fail due to substitution");
        assert!(!result.errors.is_empty(), "Errors should be present");
        assert!(result.errors[0].contains("substituted"));
    }

    #[test]
    fn test_validation_missing_dependency_warning() {
        let mut graph = DependencyGraph::new();
        graph.add_component("comp-a", "hash-a");
        graph.add_dependency("comp-a", "comp-b"); // comp-b doesn't exist

        let result = graph.validate().unwrap();
        assert!(result.valid, "Should still be valid (just a warning)");
        assert!(!result.warnings.is_empty(), "Warning should be present");
        assert!(result.warnings[0].contains("missing component"));
    }

    #[test]
    fn test_topological_sort_simple() {
        let mut graph = DependencyGraph::new();
        graph.add_component("a", "hash-a");
        graph.add_component("b", "hash-b");
        graph.add_component("c", "hash-c");

        // a -> b -> c
        graph.add_dependency("a", "b");
        graph.add_dependency("b", "c");

        let sorted = graph.topological_sort();
        assert!(sorted.is_some(), "Should be able to sort");

        let sorted = sorted.unwrap();
        assert_eq!(sorted.len(), 3);

        // In a DAG a -> b -> c, topological sort puts leaves first
        // So c (leaf) comes before b, and b comes before a (root)
        let c_pos = sorted.iter().position(|x| x == "c").unwrap();
        let b_pos = sorted.iter().position(|x| x == "b").unwrap();
        let a_pos = sorted.iter().position(|x| x == "a").unwrap();

        // Verify: c < b < a in sorted order (dependencies first)
        assert!(c_pos < b_pos, "c (no deps) should come before b (depends on c)");
        assert!(b_pos < a_pos, "b (depends on c) should come before a (depends on b)");
    }

    #[test]
    fn test_topological_sort_with_cycle() {
        let mut graph = DependencyGraph::new();
        graph.add_component("a", "hash-a");
        graph.add_component("b", "hash-b");

        // Create a cycle
        graph.add_dependency("a", "b");
        graph.add_dependency("b", "a");

        let sorted = graph.topological_sort();
        assert!(sorted.is_none(), "Should not be able to sort with cycle");
    }

    #[test]
    fn test_topological_sort_complex() {
        let mut graph = DependencyGraph::new();
        graph.add_component("a", "hash-a");
        graph.add_component("b", "hash-b");
        graph.add_component("c", "hash-c");
        graph.add_component("d", "hash-d");

        // Complex DAG:
        // a -> b
        // a -> c
        // b -> d
        // c -> d
        graph.add_dependency("a", "b");
        graph.add_dependency("a", "c");
        graph.add_dependency("b", "d");
        graph.add_dependency("c", "d");

        let sorted = graph.topological_sort();
        assert!(sorted.is_some(), "Should be able to sort");

        let sorted = sorted.unwrap();
        assert_eq!(sorted.len(), 4);

        // d should be first (no dependencies)
        // a should be last (depends on everything)
        let d_pos = sorted.iter().position(|x| x == "d").unwrap();
        let a_pos = sorted.iter().position(|x| x == "a").unwrap();

        assert!(d_pos < a_pos, "d should come before a");
    }

    #[test]
    fn test_dependency_graph_comprehensive() {
        // Create a realistic composition scenario
        let mut graph = DependencyGraph::new();

        // Add components
        graph.add_component("http-client", "sha256:abc123");
        graph.add_component("json-parser", "sha256:def456");
        graph.add_component("app-logic", "sha256:ghi789");
        graph.add_component("main-app", "sha256:jkl012");

        // Set up dependencies
        graph.add_dependency("main-app", "app-logic");
        graph.add_dependency("app-logic", "http-client");
        graph.add_dependency("app-logic", "json-parser");

        // Set actual hashes (all correct)
        graph.set_actual_hash("http-client", "sha256:abc123");
        graph.set_actual_hash("json-parser", "sha256:def456");
        graph.set_actual_hash("app-logic", "sha256:ghi789");
        graph.set_actual_hash("main-app", "sha256:jkl012");

        // Validate
        let result = graph.validate().unwrap();
        assert!(result.valid);
        assert!(result.errors.is_empty());

        // Check topological sort
        let sorted = graph.topological_sort();
        assert!(sorted.is_some());

        let sorted = sorted.unwrap();
        // main-app should be last
        assert_eq!(sorted.last(), Some(&"main-app".to_string()));
    }

    #[test]
    fn test_attack_scenario_substitution() {
        // Simulating an attack where a component has been substituted
        let mut graph = DependencyGraph::new();

        // Original manifest
        graph.add_component("crypto-lib", "sha256:trusted-hash");
        graph.add_component("app", "sha256:app-hash");
        graph.add_dependency("app", "crypto-lib");

        // Attacker substitutes crypto-lib with malicious version
        graph.set_actual_hash("crypto-lib", "sha256:malicious-hash");
        graph.set_actual_hash("app", "sha256:app-hash");

        // Validation should catch this
        let result = graph.validate().unwrap();
        assert!(!result.valid, "Attack should be detected");
        assert!(!result.errors.is_empty());
        assert!(result.errors[0].contains("crypto-lib"));
        assert!(result.errors[0].contains("malicious-hash"));
    }

    // ========================================================================
    // Phase 3: Advanced Validation Tests
    // ========================================================================

    #[test]
    fn test_version_constraint_exact() {
        let constraint = VersionConstraint::Exact("1.2.3".to_string());

        assert!(constraint.satisfies("1.2.3"));
        assert!(!constraint.satisfies("1.2.4"));
        assert!(!constraint.satisfies("1.2.2"));
    }

    #[test]
    fn test_version_constraint_minimum() {
        let constraint = VersionConstraint::Minimum("1.0.0".to_string());

        assert!(constraint.satisfies("1.0.0"));
        assert!(constraint.satisfies("1.0.1"));
        assert!(constraint.satisfies("2.0.0"));
        assert!(!constraint.satisfies("0.9.9"));
    }

    #[test]
    fn test_version_constraint_maximum() {
        let constraint = VersionConstraint::Maximum("2.0.0".to_string());

        assert!(constraint.satisfies("1.0.0"));
        assert!(constraint.satisfies("2.0.0"));
        assert!(!constraint.satisfies("2.0.1"));
        assert!(!constraint.satisfies("3.0.0"));
    }

    #[test]
    fn test_version_constraint_range() {
        let constraint = VersionConstraint::Range("1.0.0".to_string(), "2.0.0".to_string());

        assert!(!constraint.satisfies("0.9.9"));
        assert!(constraint.satisfies("1.0.0"));
        assert!(constraint.satisfies("1.5.0"));
        assert!(constraint.satisfies("2.0.0"));
        assert!(!constraint.satisfies("2.0.1"));
    }

    #[test]
    fn test_version_comparison() {
        assert_eq!(VersionConstraint::compare_versions("1.0.0", "1.0.0"), 0);
        assert_eq!(VersionConstraint::compare_versions("1.0.0", "1.0.1"), -1);
        assert_eq!(VersionConstraint::compare_versions("1.0.1", "1.0.0"), 1);
        assert_eq!(VersionConstraint::compare_versions("2.0.0", "1.9.9"), 1);
        assert_eq!(VersionConstraint::compare_versions("1.9.9", "2.0.0"), -1);
    }

    #[test]
    fn test_version_policy_exact() {
        let mut policy = VersionPolicy::new();
        policy.require_exact("crypto-lib", "1.2.3");

        assert!(policy.validate_version("crypto-lib", "1.2.3").is_ok());
        assert!(policy.validate_version("crypto-lib", "1.2.4").is_err());
        assert!(policy.validate_version("other-lib", "999.0.0").is_ok()); // No constraint
    }

    #[test]
    fn test_version_policy_minimum() {
        let mut policy = VersionPolicy::new();
        policy.require_minimum("crypto-lib", "2.0.0");

        assert!(policy.validate_version("crypto-lib", "1.9.9").is_err());
        assert!(policy.validate_version("crypto-lib", "2.0.0").is_ok());
        assert!(policy.validate_version("crypto-lib", "2.1.0").is_ok());
    }

    #[test]
    fn test_version_policy_range() {
        let mut policy = VersionPolicy::new();
        policy.require_range("lib-a", "1.0.0", "2.0.0");

        assert!(policy.validate_version("lib-a", "0.9.9").is_err());
        assert!(policy.validate_version("lib-a", "1.0.0").is_ok());
        assert!(policy.validate_version("lib-a", "1.5.0").is_ok());
        assert!(policy.validate_version("lib-a", "2.0.0").is_ok());
        assert!(policy.validate_version("lib-a", "2.0.1").is_err());
    }

    #[test]
    fn test_source_allow_list_basic() {
        let mut allow_list = SourceAllowList::new();
        allow_list.add_source("https://github.com/trusted-org");

        assert!(allow_list.is_allowed(Some("https://github.com/trusted-org/repo")));
        assert!(allow_list.is_allowed(Some("https://github.com/trusted-org")));
        assert!(!allow_list.is_allowed(Some("https://github.com/untrusted-org/repo")));
        assert!(!allow_list.is_allowed(None)); // No source not allowed by default
    }

    #[test]
    fn test_source_allow_list_with_no_source() {
        let mut allow_list = SourceAllowList::new();
        allow_list.add_source("https://github.com/trusted");
        allow_list.allow_no_source(true);

        assert!(allow_list.is_allowed(None));
        assert!(allow_list.is_allowed(Some("https://github.com/trusted/repo")));
    }

    #[test]
    fn test_source_allow_list_validation() {
        let mut allow_list = SourceAllowList::new();
        allow_list.add_source("https://internal.company.com");

        assert!(allow_list
            .validate_source("comp-a", Some("https://internal.company.com/repo"))
            .is_ok());

        let result = allow_list.validate_source("comp-b", Some("https://external.com/repo"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in allow-list"));
    }

    #[test]
    fn test_validation_mode_lenient() {
        let config = ValidationConfig::lenient();
        assert_eq!(config.mode, ValidationMode::Lenient);
    }

    #[test]
    fn test_validation_mode_strict() {
        let config = ValidationConfig::strict();
        assert_eq!(config.mode, ValidationMode::Strict);
    }

    #[test]
    fn test_validation_config_builder() {
        let mut policy = VersionPolicy::new();
        policy.require_minimum("lib-a", "1.0.0");

        let mut allow_list = SourceAllowList::new();
        allow_list.add_source("https://github.com/trusted");

        let config = ValidationConfig::strict()
            .with_version_policy(policy)
            .with_source_allow_list(allow_list)
            .with_transitive_validation(true);

        assert_eq!(config.mode, ValidationMode::Strict);
        assert!(config.version_policy.is_some());
        assert!(config.source_allow_list.is_some());
        assert!(config.validate_transitive);
    }

    #[test]
    fn test_strict_mode_converts_warnings_to_errors() {
        let mut graph = DependencyGraph::new();
        graph.add_component("comp-a", "hash-a");
        graph.add_dependency("comp-a", "comp-b"); // comp-b doesn't exist - warning

        // Lenient mode
        let lenient_config = ValidationConfig::lenient();
        let lenient_result = graph.validate_with_config(&lenient_config).unwrap();
        assert!(lenient_result.valid); // Still valid with warnings
        assert!(!lenient_result.warnings.is_empty());
        assert!(lenient_result.errors.is_empty());

        // Strict mode
        let strict_config = ValidationConfig::strict();
        let strict_result = graph.validate_with_config(&strict_config).unwrap();
        assert!(!strict_result.valid); // Not valid - warnings became errors
        assert!(!strict_result.errors.is_empty());
        assert!(strict_result.errors[0].contains("STRICT MODE"));
        assert!(strict_result.warnings.is_empty());
    }

    #[test]
    fn test_version_rollback_attack_detection() {
        // Simulating THREAT-04: Version Rollback Attack
        let mut policy = VersionPolicy::new();
        policy.require_minimum("crypto-lib", "2.0.0"); // Security fix in 2.0.0

        // Attacker tries to use vulnerable old version
        let result = policy.validate_version("crypto-lib", "1.0.0");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("does not satisfy constraint"));
    }

    #[test]
    fn test_dependency_confusion_attack_detection() {
        // Simulating THREAT-02: Dependency Confusion Attack
        let mut allow_list = SourceAllowList::new();
        allow_list.add_source("https://internal.company.com");

        // Attacker publishes to public registry
        let result = allow_list.validate_source(
            "internal-lib",
            Some("https://public-registry.com/internal-lib"),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in allow-list"));
    }

    #[test]
    fn test_comprehensive_validation_config() {
        // Complete validation scenario with all Phase 3 features
        let mut graph = DependencyGraph::new();
        graph.add_component("crypto-lib", "sha256:hash-crypto");
        graph.add_component("http-client", "sha256:hash-http");
        graph.add_component("app", "sha256:hash-app");

        graph.add_dependency("app", "crypto-lib");
        graph.add_dependency("app", "http-client");

        // Set actual hashes (all correct)
        graph.set_actual_hash("crypto-lib", "sha256:hash-crypto");
        graph.set_actual_hash("http-client", "sha256:hash-http");
        graph.set_actual_hash("app", "sha256:hash-app");

        // Create comprehensive validation config
        let mut policy = VersionPolicy::new();
        policy.require_minimum("crypto-lib", "2.0.0");

        let mut allow_list = SourceAllowList::new();
        allow_list.add_source("https://github.com/trusted-org");

        let config = ValidationConfig::strict()
            .with_version_policy(policy)
            .with_source_allow_list(allow_list)
            .with_transitive_validation(true);

        // Validate
        let result = graph.validate_with_config(&config).unwrap();
        assert!(result.valid); // Should pass basic validation
    }

    #[test]
    fn test_version_constraint_any() {
        let constraint = VersionConstraint::Any;

        assert!(constraint.satisfies("0.0.1"));
        assert!(constraint.satisfies("1.0.0"));
        assert!(constraint.satisfies("999.999.999"));
    }

    #[test]
    fn test_multiple_policies_combined() {
        let mut policy = VersionPolicy::new();
        policy.require_minimum("lib-a", "1.0.0");
        policy.require_exact("lib-b", "2.5.0");
        policy.require_range("lib-c", "1.0.0", "2.0.0");

        assert!(policy.validate_version("lib-a", "1.5.0").is_ok());
        assert!(policy.validate_version("lib-b", "2.5.0").is_ok());
        assert!(policy.validate_version("lib-c", "1.5.0").is_ok());

        assert!(policy.validate_version("lib-a", "0.9.0").is_err());
        assert!(policy.validate_version("lib-b", "2.5.1").is_err());
        assert!(policy.validate_version("lib-c", "2.1.0").is_err());
    }

    // ========================================================================
    // Phase 4: Timestamp Validation Tests
    // ========================================================================

    #[test]
    fn test_timestamp_policy_valid() {
        let policy = TimestampPolicy::new();
        let now = chrono::Utc::now().to_rfc3339();

        assert!(policy.validate_timestamp(&now, "Test").is_ok());
    }

    #[test]
    fn test_timestamp_policy_future_within_tolerance() {
        let policy = TimestampPolicy::new()
            .with_future_tolerance_seconds(300); // 5 minutes

        // 2 minutes in the future (within tolerance)
        let future = (chrono::Utc::now() + chrono::Duration::seconds(120)).to_rfc3339();
        assert!(policy.validate_timestamp(&future, "Test").is_ok());
    }

    #[test]
    fn test_timestamp_policy_future_exceeds_tolerance() {
        let policy = TimestampPolicy::new()
            .with_future_tolerance_seconds(300); // 5 minutes

        // 10 minutes in the future (exceeds tolerance)
        let future = (chrono::Utc::now() + chrono::Duration::seconds(600)).to_rfc3339();
        let result = policy.validate_timestamp(&future, "Test");

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too far in the future"));
    }

    #[test]
    fn test_timestamp_policy_max_age() {
        let policy = TimestampPolicy::new()
            .with_max_age_days(30); // 30 days

        // 10 days ago (within limit)
        let recent = (chrono::Utc::now() - chrono::Duration::days(10)).to_rfc3339();
        assert!(policy.validate_timestamp(&recent, "Test").is_ok());

        // 40 days ago (exceeds limit)
        let old = (chrono::Utc::now() - chrono::Duration::days(40)).to_rfc3339();
        let result = policy.validate_timestamp(&old, "Test");

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too old"));
    }

    #[test]
    fn test_timestamp_policy_optional_missing_required() {
        let policy = TimestampPolicy::new().require_timestamps(true);

        let result = policy.validate_optional_timestamp(None, "Test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("required but missing"));
    }

    #[test]
    fn test_timestamp_policy_optional_missing_allowed() {
        let policy = TimestampPolicy::new().require_timestamps(false);

        assert!(policy.validate_optional_timestamp(None, "Test").is_ok());
    }

    #[test]
    fn test_timestamp_policy_optional_present() {
        let policy = TimestampPolicy::new();
        let now = chrono::Utc::now().to_rfc3339();

        assert!(policy.validate_optional_timestamp(Some(&now), "Test").is_ok());
    }

    #[test]
    fn test_timestamp_policy_invalid_format() {
        let policy = TimestampPolicy::new();

        let result = policy.validate_timestamp("not-a-timestamp", "Test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid timestamp format"));
    }

    #[test]
    fn test_validate_manifest_timestamps() {
        let policy = TimestampPolicy::new();
        let now = chrono::Utc::now().to_rfc3339();

        let manifest = CompositionManifest {
            version: "1.0".to_string(),
            tool: "wac".to_string(),
            tool_version: "0.5.0".to_string(),
            timestamp: now.clone(),
            components: vec![],
            integrator: Some(IntegratorInfo {
                identity: "test@example.com".to_string(),
                signature_index: 0,
                verification_timestamp: now,
            }),
            metadata: HashMap::new(),
        };

        assert!(validate_manifest_timestamps(&manifest, &policy).is_ok());
    }

    #[test]
    fn test_validate_manifest_timestamps_old() {
        let policy = TimestampPolicy::new()
            .with_max_age_days(1);

        let old_time = (chrono::Utc::now() - chrono::Duration::days(10)).to_rfc3339();

        let manifest = CompositionManifest {
            version: "1.0".to_string(),
            tool: "wac".to_string(),
            tool_version: "0.5.0".to_string(),
            timestamp: old_time,
            components: vec![],
            integrator: None,
            metadata: HashMap::new(),
        };

        let result = validate_manifest_timestamps(&manifest, &policy);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too old"));
    }

    #[test]
    fn test_validate_provenance_timestamps() {
        let policy = TimestampPolicy::new();
        let now = chrono::Utc::now().to_rfc3339();

        let provenance = BuildProvenance {
            name: "test-component".to_string(),
            version: "1.0.0".to_string(),
            source_repo: None,
            commit_sha: None,
            build_tool: "cargo".to_string(),
            build_tool_version: "1.75.0".to_string(),
            builder: None,
            build_timestamp: now,
            metadata: HashMap::new(),
        };

        assert!(validate_provenance_timestamps(&provenance, &policy).is_ok());
    }

    // ========================================================================
    // Phase 4: Signature Freshness Tests
    // ========================================================================

    #[test]
    fn test_signature_freshness_no_restrictions() {
        let policy = SignatureFreshnessPolicy::new();
        let now = chrono::Utc::now().to_rfc3339();

        assert!(policy.validate(&now, "Signature").is_ok());
    }

    #[test]
    fn test_signature_freshness_max_age() {
        let policy = SignatureFreshnessPolicy::new()
            .with_max_age_days(30);

        // 10 days old (OK)
        let recent = (chrono::Utc::now() - chrono::Duration::days(10)).to_rfc3339();
        assert!(policy.validate(&recent, "Signature").is_ok());

        // 40 days old (too old)
        let old = (chrono::Utc::now() - chrono::Duration::days(40)).to_rfc3339();
        let result = policy.validate(&old, "Signature");

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too old"));
    }

    #[test]
    fn test_signature_freshness_minimum_timestamp() {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(7);
        let policy = SignatureFreshnessPolicy::new()
            .with_minimum_timestamp(cutoff);

        // 3 days ago (after cutoff, OK)
        let recent = (chrono::Utc::now() - chrono::Duration::days(3)).to_rfc3339();
        assert!(policy.validate(&recent, "Signature").is_ok());

        // 10 days ago (before cutoff, fail)
        let old = (chrono::Utc::now() - chrono::Duration::days(10)).to_rfc3339();
        let result = policy.validate(&old, "Signature");

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("before minimum acceptable time"));
    }

    #[test]
    fn test_signature_freshness_combined_policies() {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(60);
        let policy = SignatureFreshnessPolicy::new()
            .with_max_age_days(30)
            .with_minimum_timestamp(cutoff);

        // 15 days ago (within max age and after cutoff, OK)
        let valid = (chrono::Utc::now() - chrono::Duration::days(15)).to_rfc3339();
        assert!(policy.validate(&valid, "Signature").is_ok());

        // 45 days ago (exceeds max age but after cutoff, fail)
        let too_old = (chrono::Utc::now() - chrono::Duration::days(45)).to_rfc3339();
        assert!(policy.validate(&too_old, "Signature").is_err());

        // 90 days ago (before cutoff, fail)
        let before_cutoff = (chrono::Utc::now() - chrono::Duration::days(90)).to_rfc3339();
        assert!(policy.validate(&before_cutoff, "Signature").is_err());
    }

    // ========================================================================
    // Phase 4: Certificate Validity Tests
    // ========================================================================

    #[test]
    fn test_certificate_validity_policy_valid() {
        let policy = CertificateValidityPolicy::new();

        let not_before = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
        let not_after = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();

        assert!(policy.validate_certificate_times(&not_before, &not_after, "Test").is_ok());
    }

    #[test]
    fn test_certificate_validity_policy_expired() {
        let policy = CertificateValidityPolicy::new();

        let not_before = (chrono::Utc::now() - chrono::Duration::days(60)).to_rfc3339();
        let not_after = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();

        let result = policy.validate_certificate_times(&not_before, &not_after, "Test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn test_certificate_validity_policy_not_yet_valid() {
        let policy = CertificateValidityPolicy::new();

        let not_before = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        let not_after = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();

        let result = policy.validate_certificate_times(&not_before, &not_after, "Test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet valid"));
    }

    #[test]
    fn test_certificate_validity_policy_not_yet_valid_allowed() {
        let policy = CertificateValidityPolicy::new()
            .allow_not_yet_valid(true);

        let not_before = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        let not_after = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();

        assert!(policy.validate_certificate_times(&not_before, &not_after, "Test").is_ok());
    }

    #[test]
    fn test_certificate_validity_policy_min_remaining() {
        let policy = CertificateValidityPolicy::new()
            .with_min_remaining_validity_days(10);

        // 20 days remaining (OK)
        let not_before = (chrono::Utc::now() - chrono::Duration::days(10)).to_rfc3339();
        let not_after = (chrono::Utc::now() + chrono::Duration::days(20)).to_rfc3339();
        assert!(policy.validate_certificate_times(&not_before, &not_after, "Test").is_ok());

        // 5 days remaining (too soon)
        let not_before2 = (chrono::Utc::now() - chrono::Duration::days(10)).to_rfc3339();
        let not_after2 = (chrono::Utc::now() + chrono::Duration::days(5)).to_rfc3339();
        let result = policy.validate_certificate_times(&not_before2, &not_after2, "Test");

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expires too soon"));
    }

    #[test]
    fn test_timestamp_validation_config_integration() {
        let policy = TimestampPolicy::new()
            .with_max_age_days(30);

        let config = ValidationConfig::lenient()
            .with_timestamp_policy(policy);

        assert!(config.timestamp_policy.is_some());
    }

    #[test]
    fn test_timestamp_validation_strict_mode() {
        let policy = TimestampPolicy::new()
            .with_max_age_days(7);

        let config = ValidationConfig::strict()
            .with_timestamp_policy(policy);

        assert_eq!(config.mode, ValidationMode::Strict);
        assert!(config.timestamp_policy.is_some());
    }
}
