# WSC Asset Inventory

This document catalogs all security-relevant assets managed by WSC with their confidentiality, integrity, and availability (CIA) requirements per ISO/SAE 21434.

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Date | 2026-01-06 |
| Classification | Public |
| Review Cycle | Quarterly |
| Standard Reference | ISO/SAE 21434 Clause 15.3 |

---

## Purpose

This asset inventory supports TARA (Threat Analysis and Risk Assessment) by identifying what WSC protects and what security properties each asset requires. System integrators should reference this when performing TARA on their ITEM (vehicle, ECU, IoT device).

**Note**: This is a *component-level* asset inventory. System integrators must create their own *system-level* asset inventory that includes WSC assets alongside other system assets.

---

## Asset Categories

### 1. Cryptographic Keys

| Asset ID | Asset Name | Description | Confidentiality | Integrity | Availability |
|----------|------------|-------------|-----------------|-----------|--------------|
| KEY-001 | Ed25519 Secret Key | 64-byte signing key (seed + public) | **Critical** | **Critical** | High |
| KEY-002 | Ed25519 Public Key | 32-byte verification key | N/A (public) | **Critical** | High |
| KEY-003 | ECDSA P-256 Ephemeral Key | Short-lived Sigstore signing key | **Critical** | **Critical** | Low |
| KEY-004 | X.509 Device Private Key | Certificate-bound device identity | **Critical** | **Critical** | High |
| KEY-005 | X.509 Device Certificate | Public certificate for device | N/A (public) | High | High |

#### Security Properties Rationale

- **KEY-001 Confidentiality = Critical**: Disclosure enables unauthorized signing
- **KEY-001 Integrity = Critical**: Modification invalidates all signed modules
- **KEY-003 Availability = Low**: Generated on-demand, not persisted

---

### 2. Credentials and Tokens

| Asset ID | Asset Name | Description | Confidentiality | Integrity | Availability |
|----------|------------|-------------|-----------------|-----------|--------------|
| CRED-001 | OIDC Identity Token | Short-lived JWT for Sigstore auth | High | High | Low |
| CRED-002 | Fulcio Certificate | Ephemeral signing certificate | N/A (logged) | High | Low |
| CRED-003 | Rekor Entry UUID | Transparency log reference | N/A (public) | High | Medium |

#### Security Properties Rationale

- **CRED-001 Confidentiality = High**: Enables signing as identity until expiry (~10 min)
- **CRED-002 Integrity = High**: Tampering would invalidate signatures
- **CRED-003 Availability = Medium**: Required for keyless verification

---

### 3. WebAssembly Artifacts

| Asset ID | Asset Name | Description | Confidentiality | Integrity | Availability |
|----------|------------|-------------|-----------------|-----------|--------------|
| WASM-001 | Unsigned Module | Original WASM binary | Low | High | Medium |
| WASM-002 | Signed Module | Module with embedded signature | Low | **Critical** | High |
| WASM-003 | Signature Section | Custom section with signature data | N/A (part of module) | **Critical** | High |
| WASM-004 | Detached Signature | Separate signature file | N/A | **Critical** | High |

#### Security Properties Rationale

- **WASM-002 Integrity = Critical**: The primary purpose of WSC is protecting module integrity
- **WASM-003 Integrity = Critical**: Tampering with signature section = verification failure

---

### 4. Trust Material

| Asset ID | Asset Name | Description | Confidentiality | Integrity | Availability |
|----------|------------|-------------|-----------------|-----------|--------------|
| TRUST-001 | Public Key Set | Collection of trusted verification keys | N/A | **Critical** | High |
| TRUST-002 | Trust Bundle | Airgapped verification package | N/A | **Critical** | High |
| TRUST-003 | Certificate Pins | SHA-256 hashes of Sigstore certs | N/A | High | Medium |
| TRUST-004 | Root CA Certificate | Fulcio/custom CA root | N/A | **Critical** | High |

#### Security Properties Rationale

- **TRUST-001 Integrity = Critical**: Adding rogue key = accepting malicious modules
- **TRUST-002 Integrity = Critical**: Compromised bundle = complete bypass

---

### 5. Provenance and Metadata

| Asset ID | Asset Name | Description | Confidentiality | Integrity | Availability |
|----------|------------|-------------|-----------------|-----------|--------------|
| PROV-001 | In-toto Statement | SLSA provenance attestation | Low | High | Low |
| PROV-002 | SBOM (SPDX/CycloneDX) | Software bill of materials | Low | High | Low |
| PROV-003 | Composition Manifest | Component dependency graph | Low | High | Medium |

#### Security Properties Rationale

- **PROV-001 Integrity = High**: Tampered provenance = false supply chain claims

---

### 6. Operational Data

| Asset ID | Asset Name | Description | Confidentiality | Integrity | Availability |
|----------|------------|-------------|-----------------|-----------|--------------|
| OPS-001 | Audit Log Entries | Structured signing/verification logs | Medium | High | Medium |
| OPS-002 | Key ID Mappings | Logical name to key associations | Low | Medium | Medium |
| OPS-003 | Configuration Files | WSC runtime settings | Low | Medium | Medium |

#### Security Properties Rationale

- **OPS-001 Confidentiality = Medium**: May contain identity information
- **OPS-001 Integrity = High**: Audit trail must be tamper-evident

---

## Asset Flows

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            SIGNING FLOW                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  [WASM-001] ──────┬──────────────────────────────────────► [WASM-002]   │
│  Unsigned Module  │                                          Signed     │
│                   │                                          Module     │
│                   ▼                                                      │
│            ┌──────────────┐                                             │
│            │ WSC Signing  │◄─── [KEY-001] Secret Key                   │
│            │   Process    │◄─── [CRED-001] OIDC Token (keyless)        │
│            └──────────────┘                                             │
│                   │                                                      │
│                   ├──────────────────────────────────────► [WASM-003]   │
│                   │                                          Signature  │
│                   │                                          Section    │
│                   │                                                      │
│                   └──────────────────────────────────────► [CRED-003]   │
│                                                              Rekor UUID │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                          VERIFICATION FLOW                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  [WASM-002] ──────┬──────────────────────────────────────► [Result]     │
│  Signed Module    │                                          Pass/Fail  │
│                   │                                                      │
│                   ▼                                                      │
│            ┌──────────────┐                                             │
│            │ WSC Verify   │◄─── [KEY-002] Public Key                    │
│            │   Process    │◄─── [TRUST-001] Key Set                     │
│            └──────────────┘◄─── [TRUST-002] Trust Bundle (airgapped)   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Storage Locations

| Asset Category | Default Location | Permissions | Notes |
|----------------|------------------|-------------|-------|
| Secret Keys | `~/.wsc/keys/*.sec` | 0600 | Owner read/write only |
| Public Keys | `~/.wsc/keys/*.pub` | 0644 | World readable |
| Trust Bundles | `~/.wsc/trust/*.json` | 0644 | World readable |
| OIDC Tokens | Memory only | N/A | Zeroized after use |
| Ephemeral Keys | Memory only | N/A | Never persisted |

---

## Asset Dependencies

| Asset | Depends On | Failure Impact |
|-------|------------|----------------|
| WASM-002 (Signed Module) | KEY-001 or CRED-001 | Cannot sign |
| Verification Result | KEY-002 + TRUST-001 | Cannot verify |
| Keyless Signing | CRED-001 + CRED-002 + CRED-003 | Falls back to key-based |
| Airgapped Verification | TRUST-002 | Cannot verify offline |

---

## Threat Mapping

Each asset is subject to specific threats (see RISK_ASSESSMENT.md for full analysis):

| Asset | Primary Threats | Mitigations |
|-------|-----------------|-------------|
| KEY-001 | Theft, disclosure | 0600 permissions, zeroization, HSM (roadmap) |
| CRED-001 | Token theft | Short lifetime, zeroization |
| WASM-002 | Tampering | SHA-256 hash in signature |
| TRUST-001 | Rogue key injection | Integrity verification, pinning |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-06 | WSC Team | Initial asset inventory per ISO 21434 |
