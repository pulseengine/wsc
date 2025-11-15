# WAC Integration Roadmap

## Overview

This document outlines the implementation plan for integrating WebAssembly Composition (wac) with the certificate-based signing system.

## Current Gaps

1. **No component semantics** - Components treated as opaque binaries
2. **No composition validation** - Can't verify composition integrity
3. **No composition manifest** - No record of how components were composed
4. **No CLI integration** - Manual workflow with separate tools

## Implementation Phases

### Phase 1: Component Parsing (Priority: HIGH)

**Goal:** Understand component structure, don't just treat as opaque bytes

**Tasks:**
1. Add `wit-component` and `wit-parser` dependencies
2. Create `Component` type that wraps `Module`
3. Parse component sections (imports, exports, instances)
4. Extract WIT interfaces from components

**Files to create:**
- `src/lib/src/component/mod.rs` - Component abstraction
- `src/lib/src/component/parser.rs` - Component parsing
- `src/lib/src/component/bindings.rs` - WIT interface extraction

**API:**
```rust
pub struct Component {
    core_module: Module,
    imports: Vec<Import>,
    exports: Vec<Export>,
    instances: Vec<Instance>,
    wit_world: Option<World>,
}

impl Component {
    pub fn parse(bytes: &[u8]) -> Result<Self, WSError>;
    pub fn validate(&self) -> Result<(), WSError>;
    pub fn get_dependencies(&self) -> Vec<ComponentDependency>;
}
```

**Effort:** 3-4 days

---

### Phase 2: Composition Validation (Priority: HIGH)

**Goal:** Verify that composition is legitimate and dependencies are satisfied

**Tasks:**
1. Validate dependency graph
2. Check interface compatibility
3. Verify all sub-components are signed
4. Detect malicious substitutions

**Files to create:**
- `src/lib/src/composition/validator.rs`
- `src/lib/src/composition/graph.rs`
- `src/lib/src/composition/manifest.rs`

**API:**
```rust
pub struct CompositionValidator {
    trusted_roots: Vec<Vec<u8>>,  // Trusted CA certificates
}

impl CompositionValidator {
    pub fn validate_composition(
        &self,
        composed: &Component,
        manifest: &CompositionManifest,
    ) -> Result<ValidationReport, WSError>;

    pub fn check_dependency_signatures(
        &self,
        component: &Component,
    ) -> Result<Vec<DependencyStatus>, WSError>;
}

pub struct CompositionManifest {
    pub components: Vec<ComponentRef>,
    pub tool_version: String,
    pub composition_date: u64,
    pub dependency_graph: DependencyGraph,
    pub signatures: HashMap<String, Vec<u8>>,  // component_id → cert_chain
}

pub struct ValidationReport {
    pub all_signed: bool,
    pub all_trusted: bool,
    pub dependencies_satisfied: bool,
    pub interface_compatible: bool,
    pub warnings: Vec<String>,
}
```

**Effort:** 2-3 days

---

### Phase 3: Composition-Aware Signing (Priority: MEDIUM)

**Goal:** Sign compositions with understanding of structure

**Tasks:**
1. Sign individual sub-components separately
2. Create composition manifest
3. Embed manifest as custom section
4. Support partial re-signing (update one component)

**Files to modify:**
- `src/lib/src/provisioning/wasm_signing.rs` - Add composition awareness

**New functions:**
```rust
/// Sign a composed component with manifest
pub fn sign_composition(
    provider: &dyn SecureKeyProvider,
    key_handle: KeyHandle,
    composed: Component,
    manifest: CompositionManifest,
    certificate_chain: &[Vec<u8>],
) -> Result<Component, WSError>;

/// Verify a composed component with manifest validation
pub fn verify_composition(
    reader: &mut impl Read,
    verifier: &OfflineVerifier,
    validate_manifest: bool,
) -> Result<CompositionValidation, WSError>;

/// Re-sign just one sub-component in a composition
pub fn update_component_in_composition(
    composed: &mut Component,
    component_id: &str,
    new_component: Component,
    certificate_chain: &[Vec<u8>],
) -> Result<(), WSError>;
```

**Effort:** 3-4 days

---

### Phase 4: CLI Integration (Priority: MEDIUM)

**Goal:** Unified CLI for composition and signing

**Tasks:**
1. Add `wac` as dependency or subprocess
2. Create `compose-and-sign` subcommand
3. Support manifest generation
4. Interactive composition workflow

**Files to create:**
- `src/cli/src/commands/compose.rs`

**CLI Commands:**
```bash
# Compose and sign in one step
wsc compose \
  --component component-a.wasm \
  --component component-b.wasm \
  --certificate integrator-cert.pem \
  --key integrator-key \
  --manifest composition-manifest.json \
  --output composed.wasm

# Verify composed component
wsc verify-composition composed.wasm \
  --ca owner-root-ca.pem \
  --ca integrator-root-ca.pem \
  --check-manifest \
  --verbose

# Inspect composition
wsc inspect-composition composed.wasm \
  --show-manifest \
  --show-dependencies \
  --show-signatures

# Update one component in composition
wsc update-component composed.wasm \
  --component-id "component-a" \
  --new-component component-a-v2.wasm \
  --certificate owner-cert.pem \
  --output composed-updated.wasm
```

**Effort:** 2-3 days

---

### Phase 5: Advanced Features (Priority: LOW)

**Optional enhancements:**

1. **Composition Templates**
   ```bash
   wsc compose --template web-service.toml
   ```

2. **Dependency Resolution**
   ```bash
   wsc compose --resolve-dependencies
   ```

3. **Signature Policies**
   ```toml
   [policy]
   require-owner-signature = true
   require-integrator-signature = true
   allowed-components = ["trusted-vendor/*"]
   ```

4. **Reproducible Builds**
   - Deterministic composition
   - Build manifest with tool versions
   - Hermetic signing

**Effort:** 1-2 weeks

---

## Immediate Next Steps (This Week)

### Option A: Minimal Viable Integration (2-3 days)

**Goal:** Make composition workflows safer without full parsing

**Implement:**
1. Composition manifest custom section
2. Basic manifest validation
3. CLI helper scripts

**Deliverables:**
```bash
# Helper script
wsc-compose.sh component-a.wasm component-b.wasm composed.wasm

# Manual workflow improved:
wac compose ... > composed.wasm
wsc sign composed.wasm --manifest manifest.json ...
wsc verify composed.wasm --check-manifest ...
```

### Option B: Full Component Support (2 weeks)

**Goal:** Complete Phase 1-3 above

**Delivers:**
- Component-aware signing
- Composition validation
- Production-ready workflows

---

## Current Workaround (Use Today)

Until full integration is complete, here's the recommended workflow:

### 1. Sign Individual Components

```rust
use wsc::provisioning::*;

// Owner signs each component
for component_path in ["comp-a.wasm", "comp-b.wasm"] {
    let component = Module::deserialize_from_file(component_path)?;
    let signed = sign_with_certificate(
        &owner_provider,
        owner_key,
        component,
        &owner_cert_chain,
    )?;
    signed.serialize_to_file(&format!("{}.signed", component_path))?;
}
```

### 2. Compose with wac

```bash
# Use wac externally
wac compose \
  comp-a.wasm.signed \
  comp-b.wasm.signed \
  -o composed.wasm
```

### 3. Add Composition Metadata (Manual)

```json
// composition-manifest.json
{
  "components": [
    {"id": "comp-a", "hash": "sha256:...", "signer": "CN=Owner Device"},
    {"id": "comp-b", "hash": "sha256:...", "signer": "CN=Owner Device"}
  ],
  "composition_tool": "wac 0.5.0",
  "composition_date": "2024-11-14T12:00:00Z"
}
```

### 4. Integrator Signs

```rust
// Load composed component
let composed = Module::deserialize_from_file("composed.wasm")?;

// Integrator adds signature
let dual_signed = sign_with_certificate(
    &integrator_provider,
    integrator_key,
    composed,
    &integrator_cert_chain,
)?;

dual_signed.serialize_to_file("composed.dual-signed.wasm")?;
```

### 5. Verify All Signatures

```rust
use wsc::provisioning::*;

let mut wasm_file = std::fs::File::open("composed.dual-signed.wasm")?;

// Verify all signatures
let results = verify_all_certificates(
    &mut wasm_file,
    &[&owner_verifier, &integrator_verifier],
)?;

// Check all verified
for result in &results {
    assert!(result.verified,
        "Signature {} failed: {:?}",
        result.info.index,
        result.error
    );
}

// Manually check manifest
let manifest: CompositionManifest =
    serde_json::from_str(&std::fs::read_to_string("composition-manifest.json")?)?;
// Validate components match what was signed
```

---

## Security Implications

### Current State (Opaque Binary Signing)

**Strengths:**
- ✅ Detects any tampering with composed binary
- ✅ Multi-signature works correctly
- ✅ Certificate chains validate

**Weaknesses:**
- ⚠️  Can't detect malicious substitution of sub-components
- ⚠️  No validation of composition semantics
- ⚠️  No record of what was composed
- ⚠️  Can't verify individual components post-composition

### After Full Integration

**Additional Protections:**
- ✅ Validate all sub-components are signed
- ✅ Detect component substitution attacks
- ✅ Verify composition graph integrity
- ✅ Audit trail of composition process
- ✅ Interface compatibility checking

---

## Dependencies Needed

Add to `Cargo.toml`:

```toml
[dependencies]
# Component model support
wit-component = "0.18"
wit-parser = "0.13"
wasmparser = "0.118"

# Optional: Direct wac integration
# wac-cli = "0.5"

[dev-dependencies]
wac-parser = "0.5"  # For testing
```

---

## Testing Strategy

### Unit Tests
- Component parsing
- Manifest validation
- Dependency graph construction
- Signature verification with manifests

### Integration Tests
```rust
#[test]
fn test_compose_and_sign_workflow() {
    // Create components
    let comp_a = create_test_component("comp-a");
    let comp_b = create_test_component("comp-b");

    // Sign individually
    let signed_a = sign_with_certificate(...);
    let signed_b = sign_with_certificate(...);

    // Compose
    let composed = compose_components(&[signed_a, signed_b])?;

    // Integrator signs
    let dual_signed = sign_with_certificate(..., composed, ...)?;

    // Verify
    let results = verify_all_certificates(...)?;
    assert_eq!(results.len(), 3); // comp_a + comp_b + integrator

    // Validate manifest
    let validation = validate_composition_manifest(...)?;
    assert!(validation.all_signed);
    assert!(validation.dependencies_satisfied);
}
```

---

## Migration Path

### Backward Compatibility

All new features should be **opt-in** and **backward compatible**:

```rust
// Old code still works
sign_with_certificate(provider, key, module, certs)?;

// New composition-aware signing is explicit
sign_composition(provider, key, component, manifest, certs)?;
```

### Deprecation Strategy

1. **Phase 1-2**: Add new APIs, keep old ones
2. **Phase 3**: Mark old APIs as deprecated (6 months)
3. **Phase 4**: Remove deprecated APIs (12 months)

---

## Success Metrics

### Phase 1 Complete When:
- ✅ Can parse component bindings
- ✅ Can extract WIT interfaces
- ✅ Tests pass for component parsing

### Phase 2 Complete When:
- ✅ Can validate composition manifests
- ✅ Can detect malicious substitutions
- ✅ Dependency graph validates correctly

### Phase 3 Complete When:
- ✅ Can sign compositions with manifests
- ✅ Can verify composition integrity
- ✅ Can update components in place

### Phase 4 Complete When:
- ✅ Single CLI command for compose-and-sign
- ✅ Documentation complete
- ✅ Example workflows published

---

## Questions to Resolve

1. **Manifest format**: JSON? CBOR? Custom binary?
2. **wac dependency**: Subprocess? Library? Optional?
3. **Versioning**: How to handle component version mismatches?
4. **Trust model**: Must all sub-components be signed by same CA?

---

**Last Updated:** 2024-11-14
**Status:** Planning phase
**Next Action:** Implement Phase 1 (Component Parsing)
