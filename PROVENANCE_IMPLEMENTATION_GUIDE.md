# WASM Component Provenance Implementation Guide

**Status**: Research Complete, Ready for Implementation
**Based on**: Comprehensive research of SLSA, in-toto, SBOM, Sigstore standards
**Document**: `/docs/provenance-supply-chain-research.md`

---

## Quick Summary for wsc

### Current Position

wsc is in a **unique position** in the WASM ecosystem:

- ✅ **Excellent cryptography**: Ed25519, SHA-256, certificate chains
- ✅ **Offline-capable**: Hardware provisioning, no internet needed
- ✅ **Hardware-backed**: ATECC608 secure element integration
- ✅ **Multi-signature ready**: Component composition support
- ⚠️ **Missing provenance**: No metadata about what was composed
- ⚠️ **No dependency tracking**: Can't detect substitution attacks
- ⚠️ **No standards alignment**: Not using SLSA/in-toto formats

### Opportunity

By adding **provenance tracking + composition manifest**, wsc can become the **reference implementation** for WASM component supply chain security—filling a gap no other tool addresses.

---

## Standards Alignment

### What to Implement

| Priority | Standard | Purpose | Effort | Impact |
|----------|----------|---------|--------|--------|
| **1** | **in-toto Attestation** | Prove how components were composed | 2 weeks | HIGH - Core value |
| **2** | **SBOM (CycloneDX)** | List all components/dependencies | 1 week | HIGH - Compliance |
| **3** | **SLSA Documentation** | Show compliance levels achieved | 3 days | MEDIUM - Marketing |
| **4** | **Composition Manifest** | Track component sources + commits | 2 weeks | HIGH - Offline verification |
| **5** | **Dependency Graph** | Detect substitution/manipulation | 1 week | MEDIUM - Security |
| **6** | **Hardware Attestation** | Tie to device identity | 4 weeks | HIGH - Unique feature |
| **7** | *Optional*: Sigstore Integration | Public transparency log | 3 weeks | MEDIUM - Cloud interop |

---

## Implementation Phases

### Phase 1: Foundation (Weeks 1-2)

**Goal**: Support SBOM + in-toto attestation

#### 1.1 Design Composition Manifest

```rust
// src/lib/src/composition/manifest.rs

pub struct CompositionManifest {
    /// Manifest format version
    pub version: String,  // "1.0"
    
    /// SBOM in CycloneDX format (JSON)
    pub sbom_json: Vec<u8>,
    
    /// in-toto attestation (JSON or CBOR)
    pub attestation: Vec<u8>,
    
    /// Components list (for quick verification)
    pub components: Vec<ComponentRef> {
        pub name: String,
        pub version: String,
        pub source: String,  // git repo
        pub commit: String,
        pub hash: Vec<u8>,   // sha256
        pub signature_valid: bool,
    },
    
    /// Composition metadata
    pub composition: CompositionInfo {
        pub tool: String,      // "wac"
        pub version: String,   // "0.5.0"
        pub timestamp: u64,    // seconds since epoch
        pub composed_by: String, // device ID or user
    },
}
```

#### 1.2 SBOM Generation

- Create CycloneDX SBOM during composition
- Track component versions and hashes
- Include supplier information
- Generate purl (package URL) for each component

```rust
// In provisioning/wasm_signing.rs

pub fn generate_sbom(
    components: &[ComponentInfo],
) -> Result<Vec<u8>, WSError> {
    // Generate CycloneDX format
    let sbom = create_cyclonedx_sbom(components)?;
    Ok(serde_json::to_vec(&sbom)?)
}
```

#### 1.3 in-toto Attestation Support

- Define custom predicate for WASM composition
- Include component dependencies
- Include builder/device identity
- Timestamps and invocation info

```rust
pub fn create_composition_attestation(
    components: &[ComponentRef],
    builder_id: &str,
    artifacts_produced: &[ArtifactInfo],
) -> Result<Vec<u8>, WSError> {
    let attestation = InTotoAttestation {
        _type: "https://in-toto.io/Statement/v0.1",
        subject: vec![/* composed artifact */],
        predicate_type: "https://wasm.bytecodealliance.org/composition/v1",
        predicate: CompositionPredicate {
            build_definition: BuildDefinition {
                external_parameters: ExternalParameters {
                    components: components.to_vec(),
                    composition_tool: "wac",
                    composition_date: SystemTime::now(),
                },
                resolved_dependencies: /* component signatures */,
            },
            run_details: RunDetails {
                builder: BuilderInfo { id: builder_id.to_string() },
                metadata: Metadata {
                    started_on: SystemTime::now(),
                    finished_on: SystemTime::now(),
                    invocation_id: Uuid::new_v4().to_string(),
                },
            },
        },
    };
    
    Ok(serde_json::to_vec(&attestation)?)
}
```

#### 1.4 Integration with Signing

- Embed manifest in custom WASM section: `"composition-manifest"`
- Sign manifest along with module
- Preserve on verification

**API**:
```rust
pub fn sign_with_composition(
    provider: &dyn SecureKeyProvider,
    key: KeyHandle,
    module: &mut Module,
    manifest: CompositionManifest,
    certificates: &[Vec<u8>],
) -> Result<(), WSError>;

pub fn extract_composition_manifest(
    module: &Module,
) -> Result<CompositionManifest, WSError>;

pub fn verify_manifest(
    manifest: &CompositionManifest,
) -> Result<ManifestValidation, WSError>;
```

---

### Phase 2: Dependency Tracking (Weeks 3-4)

**Goal**: Detect composition anomalies

#### 2.1 Dependency Graph

```rust
// src/lib/src/composition/graph.rs

pub struct DependencyGraph {
    pub nodes: HashMap<String, ComponentNode>,
    pub edges: Vec<DependencyEdge>,
}

pub struct ComponentNode {
    pub id: String,
    pub name: String,
    pub version: String,
    pub hash: Vec<u8>,
    pub source: String,  // git repo
    pub commit: String,
}

pub struct DependencyEdge {
    pub from: String,  // component A
    pub to: String,    // component B
    pub interface: Option<String>,  // WIT interface
    pub required: bool,
}
```

#### 2.2 Verification

```rust
pub fn verify_composition_integrity(
    manifest: &CompositionManifest,
) -> Result<IntegrityReport, WSError> {
    let graph = build_dependency_graph(&manifest.components)?;
    
    // Check 1: All components have valid signatures
    let all_signed = verify_all_components(&graph)?;
    
    // Check 2: No component hash mismatches
    let no_substitutions = check_no_substitutions(&graph)?;
    
    // Check 3: No circular dependencies
    let no_cycles = detect_cycles(&graph)?;
    
    // Check 4: Interface compatibility (if WIT available)
    let compatible = check_interface_compatibility(&graph)?;
    
    Ok(IntegrityReport {
        all_signed,
        no_substitutions,
        no_cycles,
        compatible,
        graph,
    })
}
```

---

### Phase 3: SLSA Compliance (Week 5)

**Goal**: Document compliance levels

#### 3.1 Create `SLSA_COMPLIANCE.md`

Document how wsc achieves different SLSA levels:

**SLSA Level 3 (Keyless)**:
- ✅ Automated CI/CD (GitHub Actions)
- ✅ Signed provenance (Sigstore/Rekor)
- ✅ OIDC authentication
- ✅ Rekor transparency log

**SLSA Level 4 (Embedded)**:
- ✅ Hardware root of trust (ATECC608)
- ✅ Hermetic builds (Bazel)
- ✅ Pre-signed provenance (offline)
- ✅ Offline verification

#### 3.2 Add to CLI Help

```bash
wsc verify-composition composed.wasm \
  --check-slsa-level \
  --require-level 3
```

---

### Phase 4: Offline Provenance (Weeks 6-7)

**Goal**: Extend provisioning to include provenance

#### 4.1 Device Provisioning with Provenance

```rust
pub struct ProvisioningResult {
    pub device_id: String,
    pub key_handle: KeyHandle,
    pub certificate: Vec<u8>,
    /// NEW: Device attestation record
    pub device_attestation: DeviceAttestation {
        pub device_id: String,
        pub manufacturing_date: u64,
        pub manufacturer: String,
        pub hardware_version: String,
        pub attestation_key_cert: Vec<u8>,
    },
}
```

#### 4.2 Hardware Attestation Integration

```rust
// Use ATECC608 attestation capabilities
pub fn generate_device_attestation(
    provider: &Atecc608Provider,
    device_info: &DeviceIdentity,
) -> Result<DeviceAttestation, WSError> {
    // Generate hardware attestation using device key
    let attestation = provider.create_attestation(
        device_info.id.as_bytes(),
        SystemTime::now(),
    )?;
    
    Ok(DeviceAttestation {
        device_id: device_info.id.clone(),
        attestation: attestation,
    })
}
```

---

### Phase 5: Advanced Features (Weeks 8+)

**Goal**: Production-ready provenance system

#### 5.1 Sigstore Integration (Optional)

For systems that want cloud transparency log:

```bash
# Publish to Rekor
wsc sign-and-attest module.wasm \
  --manifest manifest.json \
  --upload-to-rekor \
  --sigstore-keyless
```

#### 5.2 Signature Policies

Policy file to enforce requirements:

```toml
[composition]
require-sbom = true
require-attestation = true
sbom-format = "cyclonedx"
attestation-format = "in-toto"

[verification]
require-all-components-signed = true
require-no-circular-deps = true
require-interface-compatibility = true

[slsa]
minimum-level = 3  # or 4 for offline
```

#### 5.3 Component Registry Integration

Optional: Publish components to registry with attestations

```bash
wsc publish component.wasm \
  --registry oci://registry.example.com \
  --include-sbom \
  --include-attestation
```

---

## Implementation Checklist

### Phase 1: Foundation

- [ ] Create `composition/mod.rs` module
- [ ] Implement `CompositionManifest` struct
- [ ] Add SBOM generation (CycloneDX)
- [ ] Add in-toto attestation creation
- [ ] Integrate with signing pipeline
- [ ] Add extraction/verification APIs
- [ ] Write tests (at least 10 test cases)
- [ ] Document manifest format
- [ ] Update README with examples

### Phase 2: Dependency Tracking

- [ ] Create `composition/graph.rs`
- [ ] Implement `DependencyGraph` struct
- [ ] Add verification functions
- [ ] Test substitution detection
- [ ] Test cycle detection
- [ ] Document threat model
- [ ] Add 10+ test cases

### Phase 3: SLSA Compliance

- [ ] Create `SLSA_COMPLIANCE.md`
- [ ] Document Level 3 achievement
- [ ] Document Level 4 achievement
- [ ] Add to website/marketing
- [ ] Include in API docs

### Phase 4: Offline Provenance

- [ ] Extend `ProvisioningResult`
- [ ] Add device attestation generation
- [ ] Integrate with ATECC608
- [ ] Test hardware attestation
- [ ] Document provisioning workflow

### Phase 5: Advanced Features

- [ ] (Optional) Sigstore integration
- [ ] (Optional) Policy file support
- [ ] (Optional) Registry publishing

---

## Testing Strategy

### Unit Tests

Create `tests/composition_tests.rs`:

```rust
#[test]
fn test_sbom_generation() { }

#[test]
fn test_attestation_creation() { }

#[test]
fn test_manifest_embedding() { }

#[test]
fn test_manifest_extraction() { }

#[test]
fn test_signature_preservation() { }

#[test]
fn test_substitution_detection() { }

#[test]
fn test_cycle_detection() { }

#[test]
fn test_interface_compatibility() { }
```

### Integration Tests

Real multi-component scenarios:

```rust
#[test]
fn test_compose_and_sign_workflow() {
    // 1. Create 3 components
    // 2. Sign each with different certs
    // 3. Compose together
    // 4. Verify manifest
    // 5. Check no substitutions possible
}

#[test]
fn test_offline_verification() {
    // 1. Create provisioned device
    // 2. Sign module on device
    // 3. Verify offline (no internet)
}
```

---

## Standards Documents to Reference

### Required Reading

1. **SLSA Framework**: https://slsa.dev/
   - 30-minute read
   - Understand 4 levels
   - Key: How does WASM fit?

2. **in-toto Attestation**: https://github.com/in-toto/attestation
   - 1-hour read
   - Understand Statement format
   - Key: Define custom predicate for WASM

3. **SBOM Basics**: https://www.cisa.gov/sbom
   - 20-minute read
   - Understand SPDX vs CycloneDX
   - Key: CycloneDX is better for software

### Optional Reading

4. **OCI 1.1 Referrers API**: https://github.com/opencontainers/spec
   - How containers do attestations
   - Could inspire WASM approach

5. **Sigstore Documentation**: https://docs.sigstore.dev/
   - How transparency logs work
   - Consider for Phase 5

---

## Migration Path for Users

### For Existing wsc Users

**Old API still works**:
```rust
sign_with_certificate(...)?;  // Still valid
```

**New API available**:
```rust
sign_with_composition(..., manifest)?;  // New: includes metadata
```

### Backward Compatibility

- Modules without manifest still verify
- Manifest is optional custom section
- No breaking changes to core signing

---

## Success Criteria

### Phase 1 Complete When:
- [ ] Can generate and embed SBOM
- [ ] Can create in-toto attestations
- [ ] Manifest roundtrips (embed → extract → verify)
- [ ] All tests passing
- [ ] Documentation complete

### Phase 2 Complete When:
- [ ] Dependency graph builds correctly
- [ ] Substitution detection works
- [ ] Cycle detection prevents malicious compositions
- [ ] Interface compatibility checker accurate

### Project Complete When:
- [ ] All 5 phases done
- [ ] 50+ test cases passing
- [ ] Compatible with SLSA Level 4
- [ ] Hardware attestation proven
- [ ] Could set ecosystem standard

---

## Timeline & Effort Estimates

| Phase | Duration | Effort | Owner |
|-------|----------|--------|-------|
| Phase 1 | 2 weeks | 80 hours | Core team |
| Phase 2 | 2 weeks | 60 hours | Core team |
| Phase 3 | 1 week | 20 hours | Technical writer |
| Phase 4 | 2 weeks | 70 hours | Embedded specialist |
| Phase 5 | 2 weeks | 50 hours | Cloud specialist |
| **Total** | **9 weeks** | **280 hours** | **Team** |

---

## Resources

### Code Files to Create

```
src/lib/src/composition/
├── mod.rs          # Module exports
├── manifest.rs     # CompositionManifest struct
├── sbom.rs         # SBOM generation
├── attestation.rs  # in-toto support
└── graph.rs        # Dependency graph

tests/
└── composition_tests.rs
```

### Documentation Files

```
docs/
├── provenance-supply-chain-research.md  (✅ done)
├── composition-manifest-format.md       (new)
├── sbom-generation-guide.md             (new)
├── in-toto-integration.md               (new)
└── slsa-compliance.md                   (new)
```

---

## Open Questions

1. **Serialization Format for Manifest**:
   - CBOR (compact, binary) vs JSON (human-readable)?
   - **Recommendation**: CBOR for embedded, JSON option for debugging

2. **SBOM Update Strategy**:
   - Can you update SBOM after initial composition?
   - **Recommendation**: Create new composition (immutable provenance)

3. **Optional vs Required**:
   - Should manifest be optional?
   - **Recommendation**: Optional by default, policy enforces requirement

4. **Transparency Log**:
   - Should we run private Rekor for embedded?
   - **Recommendation**: Optional, user decides based on use case

5. **Hardware Attestation**:
   - Standardized format for device attestation?
   - **Recommendation**: Define custom format, tie to ATECC608 capabilities

---

## Success Looks Like

When done, users can:

1. **Compose components** with full audit trail
2. **Verify offline** without internet dependency
3. **Detect attacks** (substitution, tampering, cycles)
4. **Prove compliance** with SLSA Level 4
5. **Hardware-attest** using secure element
6. **Publish SBOMs** for vulnerability scanning
7. **Integrate** with cloud pipelines (Sigstore) or edge devices (offline)

---

## Next Steps

1. **Start Phase 1**: Design CompositionManifest struct
2. **Get team feedback**: On proposed format
3. **Create first PR**: SBOM generation
4. **Iterate quickly**: Weekly PRs, incremental value

This is a **differentiator** for wsc. No other WASM tool has this.

---

**Document**: PROVENANCE_IMPLEMENTATION_GUIDE.md  
**Last Updated**: November 15, 2025  
**Status**: Ready for Implementation
