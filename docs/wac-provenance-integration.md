# WAC Composition with Provenance Tracking

## Overview

This document shows how to add **provenance tracking** to your wac composition workflow, enabling you to:
- Track where each component came from (repository, commit, builder)
- Verify the composition chain (what was composed with what)
- Detect malicious component substitution attacks
- Comply with supply chain security standards (SLSA, in-toto, SBOM)

## The Problem: Losing Provenance During Composition

### Current Workflow (No Provenance)

```bash
# Owner signs component A
wsc sign component-a.wasm --cert owner.pem -o comp-a.signed

# Owner signs component B
wsc sign component-b.wasm --cert owner.pem -o comp-b.signed

# Compose with wac
wac compose comp-a.signed comp-b.signed -o composed.wasm

# Integrator signs
wsc sign composed.wasm --cert integrator.pem -o final.wasm
```

**Problem:** `final.wasm` has signatures but **no record of**:
- Where component-a and component-b came from
- What tool composed them (wac version)
- Who built the original components
- What dependencies they had
- When composition happened

**Attack scenario:**
```
1. Component A v1.0 signed by owner (legit)
2. Attacker substitutes Component A v2.0 (also signed by owner, but malicious)
3. Composition succeeds (both signed!)
4. No way to detect the substitution
```

### Solution: Provenance Attestations

Add three layers of metadata:

1. **SBOM** (Software Bill of Materials) - What components are in this?
2. **in-toto Attestation** - How was this built/composed?
3. **Composition Manifest** - Embedded record of composition

## Standards-Based Approach

### 1. in-toto Attestation Format

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "composed.wasm",
      "digest": {"sha256": "abc123..."}
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildType": "wasm-composition@1.0",
    "builder": {
      "id": "wac@0.5.0",
      "version": "0.5.0"
    },
    "metadata": {
      "buildInvocationId": "composition-20241115-001",
      "buildStartedOn": "2024-11-15T10:00:00Z",
      "buildFinishedOn": "2024-11-15T10:00:05Z"
    },
    "materials": [
      {
        "uri": "git+https://github.com/owner/comp-a@abc123",
        "digest": {"sha256": "..."}
      },
      {
        "uri": "git+https://github.com/owner/comp-b@def456",
        "digest": {"sha256": "..."}
      }
    ]
  }
}
```

**Key elements:**
- `subject`: What was produced (composed.wasm)
- `buildType`: How it was built (wasm-composition)
- `materials`: What went into it (source components)
- `builder`: What tool was used (wac v0.5.0)

### 2. SBOM (CycloneDX Format)

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2024-11-15T10:00:00Z",
    "component": {
      "type": "application",
      "name": "composed-app",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "component-a",
      "version": "2.1.0",
      "purl": "pkg:wasm/component-a@2.1.0",
      "hashes": [{"alg": "SHA-256", "content": "..."}],
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/owner/comp-a",
          "comment": "commit abc123"
        }
      ],
      "supplier": {
        "name": "Owner Corp",
        "contact": [{"email": "security@owner.com"}]
      }
    },
    {
      "type": "library",
      "name": "component-b",
      "version": "1.5.2",
      "purl": "pkg:wasm/component-b@1.5.2",
      "hashes": [{"alg": "SHA-256", "content": "..."}],
      "supplier": {
        "name": "Owner Corp"
      }
    }
  ],
  "dependencies": [
    {"ref": "pkg:wasm/composed-app@1.0.0", "dependsOn": ["pkg:wasm/component-a@2.1.0", "pkg:wasm/component-b@1.5.2"]}
  ]
}
```

**Key elements:**
- Lists all components (name, version, hash)
- Tracks dependencies (what depends on what)
- Includes source references (git repos, commits)
- Supplier information (who built it)

### 3. Composition Manifest (Embedded in WASM)

Lightweight metadata embedded as custom section:

```json
{
  "version": "1.0",
  "composition": {
    "tool": "wac",
    "version": "0.5.0",
    "timestamp": "2024-11-15T10:00:00Z",
    "components": [
      {
        "id": "component-a",
        "hash": "sha256:...",
        "source": "git+https://github.com/owner/comp-a@abc123",
        "signature": {
          "cert_chain_index": 0,
          "signer_dn": "CN=Owner Device, O=Owner Corp"
        }
      },
      {
        "id": "component-b",
        "hash": "sha256:...",
        "source": "git+https://github.com/owner/comp-b@def456",
        "signature": {
          "cert_chain_index": 1,
          "signer_dn": "CN=Owner Device, O=Owner Corp"
        }
      }
    ],
    "integrator": {
      "cert_chain_index": 2,
      "signer_dn": "CN=Integrator Device, O=Integrator Inc"
    }
  }
}
```

## Practical Implementation

### Step 1: Capture Build Provenance (Owner)

When building components, capture provenance:

```rust
use wsc::composition::ProvenanceBuilder;

// Build component A
let prov_a = ProvenanceBuilder::new()
    .component_name("component-a")
    .version("2.1.0")
    .source_repo("https://github.com/owner/comp-a")
    .commit_sha("abc123...")
    .build_tool("cargo", "1.75.0")
    .builder_identity("Owner CI/CD", "ci@owner.com")
    .build();

// Embed provenance as custom section
let component_a = add_provenance_section(wasm_bytes, &prov_a)?;

// Sign with owner certificate
let signed_a = sign_with_certificate(
    &owner_provider,
    owner_key,
    component_a,
    &owner_cert_chain,
)?;

// Save component + provenance attestation
signed_a.serialize_to_file("component-a.signed.wasm")?;
prov_a.to_intoto_json("component-a.intoto.json")?;
```

### Step 2: Composition with Provenance Tracking

```rust
use wsc::composition::{CompositionBuilder, SBOMGenerator};

// Load signed components
let comp_a = Module::deserialize_from_file("component-a.signed.wasm")?;
let comp_b = Module::deserialize_from_file("component-b.signed.wasm")?;

// Extract their provenance
let prov_a = extract_provenance_section(&comp_a)?;
let prov_b = extract_provenance_section(&comp_b)?;

// Build composition manifest
let composition = CompositionBuilder::new()
    .add_component("component-a", &comp_a, prov_a)
    .add_component("component-b", &comp_b, prov_b)
    .composition_tool("wac", "0.5.0")
    .verify_all_signed()? // Ensure all components have valid signatures
    .build()?;

// Compose with wac (external tool)
let composed = compose_with_wac(&[comp_a, comp_b])?;

// Embed composition manifest
let composed_with_manifest = add_composition_section(composed, &composition)?;

// Generate SBOM
let sbom = SBOMGenerator::new()
    .component_name("composed-app")
    .version("1.0.0")
    .add_dependency("component-a", "2.1.0", prov_a)
    .add_dependency("component-b", "1.5.2", prov_b)
    .supplier("Integrator Inc", "security@integrator.com")
    .build_cyclonedx()?;

sbom.to_json("composed-app.sbom.json")?;

// Create in-toto attestation for composition
let attestation = composition.to_intoto_attestation(
    &composed_with_manifest,
    "wasm-composition@1.0",
)?;

attestation.to_json("composition.intoto.json")?;
```

### Step 3: Integrator Signs with Provenance

```rust
// Integrator loads composed component
let composed = Module::deserialize_from_file("composed.wasm")?;

// Verify composition manifest
let manifest = extract_composition_manifest(&composed)?;
manifest.verify_all_components_signed()?;
manifest.verify_hashes_match(&composed)?;

// Add integrator signature (preserves owner signatures + manifest)
let dual_signed = sign_with_certificate(
    &integrator_provider,
    integrator_key,
    composed,
    &integrator_cert_chain,
)?;

// Create integrator attestation
let integrator_attestation = AttestationBuilder::new()
    .subject("composed-app.wasm", &compute_hash(&dual_signed)?)
    .predicate_type("https://slsa.dev/verification/v1")
    .add_material("composition.intoto.json", &composition_hash)
    .add_material("composed-app.sbom.json", &sbom_hash)
    .verifier_identity("CN=Integrator Device, O=Integrator Inc")
    .verification_result(VerificationResult::Passed)
    .build()?;

integrator_attestation.to_json("integrator-verification.intoto.json")?;
```

### Step 4: Verification with Provenance

```rust
use wsc::composition::ProvenanceVerifier;

// Load final artifact
let final_wasm = Module::deserialize_from_file("final.wasm")?;

// Load all attestations
let attestations = vec![
    Attestation::from_json("component-a.intoto.json")?,
    Attestation::from_json("component-b.intoto.json")?,
    Attestation::from_json("composition.intoto.json")?,
    Attestation::from_json("integrator-verification.intoto.json")?,
];

// Load SBOM
let sbom = SBOM::from_json("composed-app.sbom.json")?;

// Verify provenance chain
let verifier = ProvenanceVerifier::new()
    .trust_root(owner_ca)
    .trust_root(integrator_ca)
    .require_sbom(true)
    .require_composition_manifest(true)
    .build()?;

let report = verifier.verify_full_provenance(
    &final_wasm,
    &attestations,
    &sbom,
)?;

// Check results
assert!(report.all_signatures_valid);
assert!(report.provenance_chain_intact);
assert!(report.no_component_substitution);
assert_eq!(report.components_verified, 2);

println!("✓ Provenance verified:");
println!("  - 2 components from Owner Corp");
println!("  - Composed with wac 0.5.0");
println!("  - Integrator verification passed");
println!("  - SBOM includes {} dependencies", sbom.components.len());
```

## Attack Detection

### Substitution Attack

**Scenario**: Attacker replaces component-a with malicious version

```rust
// Verification detects this:
let error = verifier.verify_full_provenance(...)?;

// Error: Component hash mismatch
// Expected (from manifest): sha256:abc123...
// Actual (from WASM): sha256:def456...
// Component: component-a
```

### Downgrade Attack

**Scenario**: Attacker uses old vulnerable version of component

```rust
// SBOM + CVE check detects this:
let vuln_check = sbom.check_vulnerabilities(cve_database)?;

// Found vulnerabilities:
// - component-a v1.0.0 (CVE-2024-12345)
//   Current version: 2.1.0 (no CVEs)
//   Severity: HIGH
```

### Composition Tampering

**Scenario**: Attacker modifies composition after signing

```rust
// Attestation verification detects this:
let error = verifier.verify_composition_attestation(...)?;

// Error: Subject digest mismatch
// Attestation claims: sha256:abc...
// Actual file: sha256:def...
// File has been modified after composition
```

## Migration Path

### Phase 1: Add Provenance Capture (Week 1)

**Minimal impact on existing workflow:**

```bash
# Build with provenance
cargo build --release
wsc provenance capture \
  --component target/wasm32/component-a.wasm \
  --repo https://github.com/owner/comp-a \
  --commit $(git rev-parse HEAD) \
  --output component-a.provenance.json

# Sign (existing workflow)
wsc sign component-a.wasm --cert owner.pem -o component-a.signed.wasm

# Attach provenance (new)
wsc provenance attach \
  --wasm component-a.signed.wasm \
  --attestation component-a.provenance.json \
  --output component-a.final.wasm
```

### Phase 2: Add SBOM Generation (Week 2)

```bash
# Compose (existing)
wac compose comp-a.final.wasm comp-b.final.wasm -o composed.wasm

# Generate SBOM (new)
wsc sbom generate \
  --input composed.wasm \
  --name composed-app \
  --version 1.0.0 \
  --format cyclonedx \
  --output composed-app.sbom.json
```

### Phase 3: Full Provenance Chain (Week 3)

```bash
# Composition with full provenance
wsc compose-with-provenance \
  --component comp-a.final.wasm \
  --component comp-b.final.wasm \
  --output composed.wasm \
  --sbom-output composed.sbom.json \
  --attestation-output composition.intoto.json

# Integrator verification + signing
wsc verify-and-sign \
  --input composed.wasm \
  --sbom composed.sbom.json \
  --attestations composition.intoto.json \
  --cert integrator.pem \
  --output final.wasm
```

### Phase 4: Automated Verification (Week 4+)

```bash
# Deploy-time verification
wsc verify-deployment final.wasm \
  --require-provenance \
  --require-sbom \
  --check-cves \
  --allowed-signers owner-ca.pem,integrator-ca.pem
```

## Data Flow Diagram

```
┌─────────────┐
│ Build (CI)  │
│ component-a │
└──────┬──────┘
       │
       ├──> component-a.wasm
       ├──> component-a.provenance.json (in-toto)
       └──> Sign with owner cert
              │
              ├──> component-a.signed.wasm (with embedded provenance)
              │
┌─────────────┴────────┐
│ Composition (wac)    │
│ comp-a + comp-b      │
└──────┬───────────────┘
       │
       ├──> composed.wasm
       ├──> composition.intoto.json (attestation)
       ├──> composed.sbom.json (SBOM)
       └──> Manifest embedded in WASM
              │
┌─────────────┴────────┐
│ Integration          │
│ Verify + Sign        │
└──────┬───────────────┘
       │
       ├──> final.wasm (multi-signature)
       ├──> integrator.intoto.json (verification attestation)
       └──> All metadata attached
              │
┌─────────────┴────────┐
│ Deployment           │
│ Full Verification    │
└──────────────────────┘
       │
       └──> ✓ Provenance chain valid
            ✓ All signatures verified
            ✓ SBOM checked
            ✓ No CVEs found
            ✓ Composition integrity confirmed
```

## File Structure

After implementing provenance tracking:

```
project/
├── components/
│   ├── component-a.wasm               # Original WASM
│   ├── component-a.provenance.json    # Build provenance (in-toto)
│   ├── component-a.signed.wasm        # Signed with embedded provenance
│   └── component-b.signed.wasm
│
├── composed/
│   ├── composed.wasm                  # Composed WASM (with manifest section)
│   ├── composed.sbom.json             # SBOM (CycloneDX format)
│   ├── composition.intoto.json        # Composition attestation
│   └── integrator.intoto.json         # Integrator verification
│
└── final/
    └── final.wasm                     # Final multi-signed artifact
        (contains):
        - WASM code
        - Composition manifest (custom section)
        - Owner signatures (2)
        - Integrator signature (1)
        - Provenance pointers
```

External attestations and SBOM are referenced from manifest.

## Standards Compliance

| Standard | Level | Status After Implementation |
|----------|-------|----------------------------|
| **SLSA** | Level 3 | ✅ With cloud CI/CD |
| **SLSA** | Level 4 | ✅ With offline hardware keys |
| **in-toto** | Full | ✅ Attestation format |
| **SBOM** | NTIA Minimum | ✅ CycloneDX format |
| **SBOM** | Full | ✅ Dependencies + supplier |
| **Sigstore** | Optional | ⚠️ Can integrate |

## Security Properties

### With Provenance Tracking

**What's guaranteed:**
1. **Component origin** - Know where each component came from
2. **Build reproducibility** - Can recreate exact build
3. **Composition integrity** - Detect any modifications
4. **Signer accountability** - Clear chain of custody
5. **Substitution prevention** - Hash + signature binding
6. **CVE detection** - SBOM enables vulnerability scanning

**Attack resistance:**
- ✅ Component substitution → Detected (hash mismatch)
- ✅ Composition tampering → Detected (attestation failure)
- ✅ Downgrade attack → Detected (SBOM + CVE check)
- ✅ Supply chain compromise → Detected (multi-signature requirement)
- ✅ Unsigned components → Detected (manifest validation)

## Next Steps

1. **Review** `/home/user/wsc/PROVENANCE_IMPLEMENTATION_GUIDE.md` for implementation details
2. **Decide** on manifest format (CBOR vs JSON)
3. **Implement** Phase 1 (manifest + SBOM generation)
4. **Test** with example components
5. **Document** migration guide for users

## References

- [SLSA Framework](https://slsa.dev/)
- [in-toto Attestation Format](https://github.com/in-toto/attestation)
- [CycloneDX SBOM Spec](https://cyclonedx.org/)
- [NTIA SBOM Minimum Elements](https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf)
- [Sigstore](https://www.sigstore.dev/)

---

**Status**: Design Complete - Ready for Implementation
**Estimated Effort**: 4-6 weeks for full provenance support
**Impact**: High - Unique in WASM ecosystem
