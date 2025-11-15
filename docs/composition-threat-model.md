# WebAssembly Component Composition - Threat Model

**Document Version**: 1.0
**Last Updated**: November 15, 2025
**Status**: Active

## Overview

This document outlines the security threats faced by WebAssembly component composition workflows and describes how wsc's provenance tracking and validation mechanisms mitigate these threats.

---

## Threat Actors

### 1. External Attacker
- **Motivation**: Compromise supply chain to inject malicious code
- **Capabilities**: Can intercept/modify components during download
- **Access Level**: Network-level access, no internal access

### 2. Malicious Dependency Author
- **Motivation**: Distribute malicious components as legitimate libraries
- **Capabilities**: Full control over specific component code
- **Access Level**: Can publish components to registries

### 3. Compromised Build System
- **Motivation**: Inject malicious code during composition
- **Capabilities**: Modify components during build/composition process
- **Access Level**: Build environment access

### 4. Insider Threat
- **Motivation**: Sabotage or data exfiltration
- **Capabilities**: Direct access to composition tools and keys
- **Access Level**: Developer/integrator access

---

## Threat Categories

### THREAT-01: Component Substitution Attack

**Description**: Attacker replaces a legitimate component with a malicious version that has the same name but different content.

**Attack Vector**:
```
Original:  crypto-lib v1.0 (hash: abc123)
Malicious: crypto-lib v1.0 (hash: xyz789) ← Different hash, same name/version
```

**Impact**: **CRITICAL**
- Malicious code execution with full component permissions
- Data exfiltration or corruption
- Complete compromise of composed application

**Mitigation**:
- ✅ **Dependency Graph Hash Validation**: wsc tracks expected hashes in `CompositionManifest`
- ✅ **Substitution Detection**: `DependencyGraph.detect_substitutions()` catches hash mismatches
- ✅ **Validation Failure**: Composition validation fails with detailed error message

**Detection Code**:
```rust
let mut graph = DependencyGraph::from_manifest(&manifest);

// Set actual hashes from filesystem
for component in components {
    graph.set_actual_hash(&component.id, &actual_hash);
}

// Validate - will fail if substitution detected
let result = graph.validate()?;
if !result.valid {
    // Errors contain: "Component 'X' substituted: expected hash 'Y', actual hash 'Z'"
    return Err(CompositionError::ValidationFailed(result.errors));
}
```

**Residual Risk**: **LOW** (with proper implementation)
- Requires attacker to also compromise manifest or bypass hash validation

---

### THREAT-02: Dependency Confusion Attack

**Description**: Attacker uploads a malicious component with the same name to a public registry, confusing the build system into using the wrong component.

**Attack Vector**:
```
Internal: company/internal-lib (private registry)
Malicious: company/internal-lib (public registry) ← Same name, different source
```

**Impact**: **HIGH**
- Unintended code execution
- Potential data exposure to attacker-controlled servers

**Mitigation**:
- ✅ **Source Tracking**: `ComponentRef.source` records repository URL
- ✅ **SBOM with VCS References**: CycloneDX SBOM includes `externalReferences` with VCS links
- ⚠️ **Partial**: Requires verification of source URLs against allow-list

**Detection Code**:
```rust
let sbom = extract_sbom(&module)?;
for component in &sbom.components {
    for ext_ref in &component.external_references {
        if ext_ref.ref_type == "vcs" {
            // Verify URL is from approved source
            if !is_approved_source(&ext_ref.url) {
                return Err(UnauthorizedSource);
            }
        }
    }
}
```

**Residual Risk**: **MEDIUM**
- Requires manual configuration of approved source list
- Source URLs can be spoofed if not verified

---

### THREAT-03: Circular Dependency Attack

**Description**: Attacker creates circular dependencies to cause build failures, denial of service, or infinite loops during composition.

**Attack Vector**:
```
component-a depends on component-b
component-b depends on component-c
component-c depends on component-a  ← Cycle!
```

**Impact**: **MEDIUM**
- Build system hangs or crashes
- Resource exhaustion
- Denial of service for composition pipeline

**Mitigation**:
- ✅ **Cycle Detection**: `DependencyGraph.detect_cycles()` uses DFS to find cycles
- ✅ **Validation Failure**: Composition fails with cycle path
- ✅ **Topological Sort Failure**: Returns `None` if cycles exist

**Detection Code**:
```rust
let graph = DependencyGraph::from_manifest(&manifest);

if let Some(cycle) = graph.detect_cycles() {
    // cycle = ["a", "b", "c", "a"]
    eprintln!("Cycle detected: {}", cycle.join(" -> "));
    return Err(CyclicDependency);
}
```

**Residual Risk**: **VERY LOW**
- Fully mitigated by cycle detection algorithm
- No known bypasses

---

### THREAT-04: Version Rollback Attack

**Description**: Attacker replaces a component with an older, vulnerable version that is still validly signed.

**Attack Vector**:
```
Current:   crypto-lib v2.0 (no vulnerabilities)
Rollback:  crypto-lib v1.0 (has CVE-2024-1234)
```

**Impact**: **HIGH**
- Reintroduction of known vulnerabilities
- Exploitation of patched security flaws

**Mitigation**:
- ⚠️ **Partial**: Version tracking in manifest and SBOM
- ⚠️ **Incomplete**: No automatic version policy enforcement
- ✅ **Detection**: Manual inspection of manifest shows version mismatch

**Current Capabilities**:
```rust
let manifest = extract_composition_manifest(&module)?;
for component in &manifest.components {
    // Version is available but not validated against policy
    println!("Component: {} (no version policy check)", component.id);
}
```

**Residual Risk**: **MEDIUM-HIGH**
- Requires manual version policy enforcement
- **Recommendation**: Implement minimum version requirements in Phase 3

---

### THREAT-05: Transitive Dependency Poisoning

**Description**: Attacker compromises a deep dependency (dependency of a dependency) that isn't directly visible in the composition manifest.

**Attack Vector**:
```
app depends on lib-a
lib-a depends on lib-b (compromised)  ← Not directly visible
```

**Impact**: **HIGH**
- Harder to detect than direct dependencies
- Can affect many applications indirectly

**Mitigation**:
- ✅ **Transitive Dependency Tracking**: Supported via dependency graph
- ✅ **SBOM Coverage**: CycloneDX SBOM includes all components and dependencies
- ⚠️ **Partial**: Requires recursive hash validation

**Detection Approach**:
```rust
// Build full dependency graph including transitive deps
let mut graph = DependencyGraph::new();

// Recursively add all dependencies
fn add_all_deps(graph: &mut DependencyGraph, component: &Component) {
    graph.add_component(&component.id, &component.hash);
    for dep in &component.dependencies {
        add_all_deps(graph, dep);
        graph.add_dependency(&component.id, &dep.id);
    }
}

// Validate entire graph
graph.validate()?;
```

**Residual Risk**: **MEDIUM**
- Requires full dependency tree resolution
- **Recommendation**: Add recursive dependency validation in Phase 3

---

### THREAT-06: Build-Time Injection

**Description**: Attacker compromises the composition/build tool itself to inject malicious code during the composition process.

**Attack Vector**:
```
Legitimate components → [Compromised wac/builder] → Malicious composed output
```

**Impact**: **CRITICAL**
- Complete bypass of component-level security
- Affects all builds from compromised system

**Mitigation**:
- ✅ **in-toto Attestation**: Records builder identity and materials
- ✅ **Multi-Signature Support**: Owner + Integrator both sign
- ✅ **Device Attestation**: Hardware-backed proof of builder identity (Phase 5)
- ✅ **Hardware Security**: ATECC608/TPM-based signing
- ✅ **Transparency Log**: Optional Rekor integration for build audit trail

**Detection Code**:
```rust
let attestation = extract_intoto_attestation(&module)?;

// Verify builder identity
if attestation.predicate.builder.id != expected_builder_id {
    return Err(UntrustedBuilder);
}

// Verify all materials match manifest
for material in &attestation.predicate.materials {
    let expected_hash = manifest.get_component_hash(&material.uri)?;
    let actual_hash = material.digest.get("sha256")?;
    if expected_hash != actual_hash {
        return Err(MaterialMismatch);
    }
}

// NEW in Phase 5: Verify device attestation
let device_attestation = extract_device_attestation(&module)?
    .ok_or("Device attestation required for hardware builds")?;

validate_device_attestation(&device_attestation, Some(expected_device_id))?;

// Verify hardware model matches policy
if device_attestation.hardware_model != "ATECC608" {
    return Err(UnauthorizedHardware);
}
```

**Residual Risk**: **LOW** (Phase 5 Complete)
- Fully mitigated with hardware attestation
- Device-specific signing prevents unauthorized builders
- **Status**: ✅ Implemented in Phase 5

---

### THREAT-07: Timestamp Manipulation

**Description**: Attacker manipulates timestamps to hide when malicious components were introduced or to bypass expiration policies.

**Attack Vector**:
```
Malicious component created: 2025-11-15
Timestamp manipulated to:    2024-01-01  ← Appears older than it is
```

**Impact**: **LOW-MEDIUM**
- Can bypass time-based policies
- Makes forensic analysis harder

**Mitigation**:
- ✅ **Timestamp Recording**: All provenance includes ISO 8601 timestamps
- ✅ **Timestamp Validation**: Implemented in Phase 4
- ✅ **Age Limits**: Configurable maximum age for timestamps
- ✅ **Future Tolerance**: Clock skew protection (default 5 minutes)
- ✅ **Certificate Expiration**: X.509 validity period checking
- ✅ **Signature Freshness**: Time window validation for signatures

**Detection Code**:
```rust
use wsc::composition::{TimestampPolicy, validate_all_timestamps};

let policy = TimestampPolicy::new()
    .with_max_age_days(30)  // Reject timestamps older than 30 days
    .with_future_tolerance_seconds(300);  // Allow 5 min clock skew

let result = validate_all_timestamps(&module, &policy)?;
if !result.valid {
    for error in &result.errors {
        eprintln!("Timestamp validation failed: {}", error);
    }
}
```

**Certificate Validation Code**:
```rust
use wsc::composition::CertificateValidityPolicy;

let cert_policy = CertificateValidityPolicy::new()
    .with_min_remaining_validity_days(10);  // Require 10 days remaining

cert_policy.validate_certificate_der(cert_der, "Signing certificate")?;
```

**Residual Risk**: **VERY LOW** (Phase 4 Complete)
- Fully mitigated with timestamp validation
- **Status**: ✅ Implemented in Phase 4

---

### THREAT-08: Missing Component Attack

**Description**: Required dependency is missing from the composition, causing runtime failures or falling back to unsafe defaults.

**Attack Vector**:
```
app depends on crypto-lib, auth-lib
Composition only includes: crypto-lib  ← auth-lib missing!
```

**Impact**: **MEDIUM-HIGH**
- Runtime failures
- Potential security bypasses if fallback to insecure defaults

**Mitigation**:
- ✅ **Missing Dependency Detection**: `validate()` reports warnings for missing components
- ⚠️ **Warning Only**: Does not fail validation by default

**Detection Code**:
```rust
let result = graph.validate()?;

for warning in &result.warnings {
    if warning.contains("missing component") {
        eprintln!("WARNING: {}", warning);
        // Optionally treat as error
    }
}
```

**Residual Risk**: **MEDIUM**
- Warnings can be ignored
- **Recommendation**: Add strict mode that treats warnings as errors

---

## Attack Scenarios and Mitigations

### Scenario 1: Supply Chain Compromise

**Attack Flow**:
1. Attacker compromises component repository
2. Replaces crypto-lib v1.0 with malicious version
3. Developer downloads and composes application
4. Malicious code included in production

**Defenses**:
- Manifest records expected hash of crypto-lib
- Dependency graph validation detects hash mismatch
- Composition fails with clear error message
- **Result**: ✅ Attack detected and prevented

---

### Scenario 2: Malicious Insider

**Attack Flow**:
1. Malicious integrator has access to signing keys
2. Composes application with backdoored component
3. Signs with legitimate integrator key
4. Deploys to production

**Defenses**:
- Multi-signature requirement: Owner + Integrator
- in-toto attestation records materials and builder
- Post-deployment audit can detect:
  - Unexpected components in SBOM
  - Hash mismatches in attestation materials
- **Result**: ⚠️ Partially mitigated (requires post-deployment audit)

---

### Scenario 3: Dependency Confusion

**Attack Flow**:
1. Attacker publishes "company-internal-lib" to public registry
2. Build system checks public registry first
3. Downloads malicious version instead of internal version
4. Composes with wrong component

**Defenses**:
- SBOM records VCS URL in externalReferences
- Source URL validation detects public vs private registry
- **Result**: ⚠️ Requires manual source allow-list configuration

---

## Risk Matrix

| Threat | Likelihood | Impact | Current Mitigation | Residual Risk |
|--------|------------|--------|-------------------|---------------|
| THREAT-01: Component Substitution | Medium | Critical | Full detection | **LOW** |
| THREAT-02: Dependency Confusion | Medium | High | Partial (source tracking) | **MEDIUM** |
| THREAT-03: Circular Dependencies | Low | Medium | Full detection | **VERY LOW** |
| THREAT-04: Version Rollback | Medium | High | Partial (version tracking) | **MEDIUM-HIGH** |
| THREAT-05: Transitive Deps | Medium | High | Partial (SBOM) | **MEDIUM** |
| THREAT-06: Build-Time Injection | Low | Critical | Full (hardware attestation) | **LOW** |
| THREAT-07: Timestamp Manipulation | Low | Low | Full validation (Phase 4) | **VERY LOW** |
| THREAT-08: Missing Components | Medium | Medium-High | Warning only | **MEDIUM** |

---

## Security Recommendations

### Immediate (Phase 2)
- ✅ Dependency graph validation
- ✅ Cycle detection
- ✅ Substitution detection
- ✅ Threat model documentation

### Phase 3
- [ ] Version policy enforcement (minimum/maximum versions)
- [ ] Recursive transitive dependency validation
- [ ] Strict mode (warnings as errors)
- [ ] Source URL allow-list configuration

### Phase 4 - ✅ COMPLETE!
- [x] Timestamp validation against trusted time source ✅
- [x] Certificate expiration checking ✅
- [x] Signature freshness validation ✅
- [x] 80 composition tests passing (58 + 22 new tests) ✅
- [x] THREAT-07 fully mitigated ✅

### Phase 5 - ✅ COMPLETE!
- [x] Hardware-backed builder attestation (ATECC608) ✅
- [x] Device attestation structures ✅
- [x] Transparency log integration structures ✅
- [x] SLSA Level 3/4 compliance documentation ✅
- [x] 104 composition tests passing (80 + 24 new tests) ✅
- [x] THREAT-06 residual risk reduced (MEDIUM → LOW) ✅

---

## Operational Security Practices

### For Component Owners
1. **Always sign components** with private keys
2. **Record source repository** in component metadata
3. **Use semantic versioning** consistently
4. **Pin dependency versions** in manifests

### For Integrators
1. **Validate all dependencies** before composition
2. **Review SBOM** for unexpected components
3. **Verify source URLs** against approved list
4. **Enable strict validation mode**
5. **Sign composed output** with integrator key

### For Verifiers
1. **Check all signatures** (owner + integrator)
2. **Inspect in-toto attestation** materials
3. **Validate dependency graph** for cycles and substitutions
4. **Compare SBOM** against expected components
5. **Audit timestamps** for anomalies

---

## Compliance and Standards

### SLSA Framework
- **Current Level**: SLSA Level 2 (achieved)
  - Provenance: ✅ Available
  - Build service: ✅ Automated
  - Provenance authenticity: ✅ Signed

- **Target Level**: SLSA Level 3
  - Non-falsifiable provenance: ⚠️ Partial (need hardware attestation)
  - Isolated build: ⚠️ Depends on deployment

### in-toto
- ✅ Attestation format compliance
- ✅ Material tracking
- ✅ Builder identity recording
- ⚠️ Supply chain layout (planned Phase 4)

### CycloneDX SBOM
- ✅ Version 1.5 compliance
- ✅ Component tracking
- ✅ External references
- ✅ Dependency relationships

---

## Appendix: Validation Example

```rust
use wsc::composition::*;

// Extract provenance from composed WASM
let module = Module::deserialize_from_file("app.wasm")?;
let manifest = extract_composition_manifest(&module)?.ok_or(NoManifest)?;
let sbom = extract_sbom(&module)?.ok_or(NoSbom)?;
let attestation = extract_intoto_attestation(&module)?.ok_or(NoAttestation)?;

// Build dependency graph
let mut graph = DependencyGraph::from_manifest(&manifest);

// Set actual hashes from components on disk
for component in &manifest.components {
    let actual_hash = compute_component_hash(&component.id)?;
    graph.set_actual_hash(&component.id, &actual_hash);
}

// Add dependencies from SBOM
for dependency in &sbom.dependencies {
    graph.add_dependency(&dependency.component_ref, &dependency.depends_on);
}

// Validate
let result = graph.validate()?;

if !result.valid {
    eprintln!("❌ Validation FAILED");
    for error in &result.errors {
        eprintln!("  ERROR: {}", error);
    }
    return Err(ValidationFailed);
}

if !result.warnings.is_empty() {
    eprintln!("⚠️  Validation succeeded with warnings:");
    for warning in &result.warnings {
        eprintln!("  WARNING: {}", warning);
    }
}

println!("✅ Validation PASSED");

// Verify in-toto attestation materials match manifest
for material in &attestation.predicate.materials {
    let component_id = material.uri.trim_end_matches(".wasm");
    let expected_hash = manifest.get_component_hash(component_id)?;
    let actual_hash = material.digest.get("sha256").ok_or(MissingHash)?;

    if expected_hash != actual_hash {
        return Err(MaterialMismatch { component_id, expected_hash, actual_hash });
    }
}

println!("✅ in-toto attestation verified");
```

---

**Document Status**: ACTIVE
**Review Cycle**: Quarterly
**Next Review**: February 15, 2026
