# WSC Security Evidence for TARA

This document provides **component-level security evidence** that system integrators can reference when performing TARA (Threat Analysis and Risk Assessment) on their systems.

> **Critical Distinction**: WSC does not "perform TARA" - it provides evidence FOR your TARA.
>
> - **Your responsibility**: Perform TARA on your ITEM (vehicle ECU, IoT device, etc.)
> - **WSC provides**: Component security claims, threat analysis, risk assessment evidence
> - **See also**: `docs/security/INTEGRATION_GUIDANCE.md` for integration help

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.1 |
| Date | 2026-01-06 |
| Standards | ISO/SAE 21434, IEC 62443, SLSA |
| Status | Active |
| Scope | Component-level evidence only |

---

## ISO/SAE 21434 (Automotive Cybersecurity)

### Work Products Mapping

WSC provides **component-level evidence** for the following work products. System integrators must create their own system-level work products.

| WP ID | Work Product | WSC Evidence | Evidence Status | Notes |
|-------|--------------|--------------|-----------------|-------|
| WP-06-01 | Threat Analysis | docs/THREAT_MODEL.md | Component-level | Covers WSC threats only |
| WP-06-02 | Risk Assessment | docs/security/RISK_ASSESSMENT.md | Component-level | ISO 21434 AF ratings |
| WP-07-01 | Cybersecurity Goals | Security claims below | Component-level | Goals for WSC component |
| WP-07-02 | Cybersecurity Claims | This document | Component-level | Claims for WSC only |
| WP-08-01 | Vulnerability Analysis | Fuzz testing results | Component-level | 6 fuzz targets |
| WP-09-01 | Verification | cargo test, fuzz | Component-level | Test coverage reports |

**Note**: "Complete" status for component evidence does NOT mean your system TARA is complete.

### Cybersecurity Goals

| Goal ID | Goal | Implementation |
|---------|------|----------------|
| CG-01 | Authenticity of WASM modules | Ed25519 signatures |
| CG-02 | Integrity of signed content | SHA-256 hash verification |
| CG-03 | Non-repudiation of signing | Rekor transparency log |
| CG-04 | Confidentiality of keys | Secure storage, zeroization |
| CG-05 | Availability of verification | Offline verification support |

### Cybersecurity Requirements

| Req ID | Requirement | WSC Control | Evidence |
|--------|-------------|-------------|----------|
| CR-01 | Use approved cryptographic algorithms | Ed25519, SHA-256 | src/signature/ |
| CR-02 | Protect cryptographic keys | 0600 permissions, zeroize | secure_file.rs, keys.rs |
| CR-03 | Verify software integrity | Signature verification | simple.rs, multi.rs |
| CR-04 | Implement defense in depth | Multi-layer security | cert_pinning.rs |
| CR-05 | Log security events | Rekor integration | rekor.rs |
| CR-06 | Support incident response | Key revocation docs | INCIDENT_RESPONSE.md |

---

## IEC 62443 (Industrial Automation Cybersecurity)

### Security Level Capability

**WSC Component Security Level (SL-C) = 2**

WSC is a software component. Its security level capability is:

| SL | Description | WSC Capability | Status |
|----|-------------|----------------|--------|
| SL 1 | Casual/coincidental | Software key storage, basic verification | **Supported** |
| SL 2 | Intentional, low resources | + Certificate pinning, file permissions, zeroization | **Supported** |
| SL 3 | Sophisticated attacker | + HSM integration required | **Requires HSM** |
| SL 4 | State-level threat | + TEE, secure boot, anti-tamper | **Not Supported** |

**Important Clarifications:**

- **SL-C (Component)**: What WSC can achieve = **2**
- **SL-T (Target)**: What your system aims for = **Determined by you**
- Achieving SL-T = 3 with WSC requires enabling HSM backend via `platform/` module (in development)
- SL-T = 4 requires external TEE and secure boot chain beyond WSC's scope

### Foundational Requirements (FR)

#### FR 1: Identification and Authentication Control

| SR | Requirement | WSC Implementation |
|----|-------------|-------------------|
| SR 1.1 | Human user identification | OIDC identity binding |
| SR 1.2 | Software process identification | Key ID in signatures |
| SR 1.3 | Account management | N/A (delegated to OIDC) |
| SR 1.5 | Authenticator management | Key lifecycle docs |
| SR 1.7 | Strength of authentication | Ed25519 (128-bit security) |

#### FR 2: Use Control

| SR | Requirement | WSC Implementation |
|----|-------------|-------------------|
| SR 2.1 | Authorization enforcement | Signature verification |
| SR 2.4 | Mobile code | WASM module integrity |
| SR 2.8 | Auditable events | Rekor log entries |
| SR 2.9 | Audit storage capacity | Sigstore infrastructure |

#### FR 3: System Integrity

| SR | Requirement | WSC Implementation |
|----|-------------|-------------------|
| SR 3.1 | Communication integrity | TLS + cert pinning |
| SR 3.2 | Protection from malicious code | Signature verification |
| SR 3.4 | Software/info integrity | SHA-256 + Ed25519 |
| SR 3.5 | Input validation | Bounded parsing, fuzz testing |

#### FR 4: Data Confidentiality

| SR | Requirement | WSC Implementation |
|----|-------------|-------------------|
| SR 4.1 | Information confidentiality | Key zeroization |
| SR 4.2 | Information at rest | Secure file permissions |
| SR 4.3 | Use of cryptography | Ed25519, SHA-256 |

#### FR 5: Restricted Data Flow

| SR | Requirement | WSC Implementation |
|----|-------------|-------------------|
| SR 5.1 | Network segmentation | N/A (application level) |
| SR 5.2 | Zone boundary protection | Airgapped mode support |

#### FR 6: Timely Response to Events

| SR | Requirement | WSC Implementation |
|----|-------------|-------------------|
| SR 6.1 | Audit log accessibility | Rekor public log |
| SR 6.2 | Continuous monitoring | Transparency log monitoring |

#### FR 7: Resource Availability

| SR | Requirement | WSC Implementation |
|----|-------------|-------------------|
| SR 7.1 | DoS protection | Resource limits (16 MB) |
| SR 7.2 | Resource management | Bounded allocations |
| SR 7.6 | Network/security config | Offline verification |

---

## SLSA (Supply Chain Levels for Software Artifacts)

### Level Compliance

| Level | Requirement | WSC Status |
|-------|-------------|------------|
| SLSA 1 | Provenance exists | Provenance embedding |
| SLSA 2 | Hosted build, signed provenance | Keyless signing + Rekor |
| SLSA 3 | Hardened build | Reproducible builds (roadmap) |
| SLSA 4 | Hermetic, reproducible | Full hermetic (roadmap) |

### Build Requirements

| Requirement | WSC Implementation |
|-------------|-------------------|
| Signed provenance | composition/intoto.rs |
| Timestamp from service | Rekor timestamp |
| Version control identity | OIDC identity binding |
| Dependencies declared | SBOM embedding |

---

## Common Criteria (EAL2+)

For Common Criteria evaluation at EAL2 or above:

### Security Functional Requirements

| SFR Class | SFR | WSC Control |
|-----------|-----|-------------|
| FCS_COP | Cryptographic operation | Ed25519, SHA-256 |
| FCS_CKM | Cryptographic key management | Key generation, zeroization |
| FDP_ITC | Import from outside TSF | Signature verification |
| FDP_ETC | Export to outside TSF | Signature embedding |
| FIA_UID | User identification | OIDC identity |
| FPT_FLS | Fail secure | panic=abort, error handling |

### Security Assurance Requirements

| SAR | Requirement | WSC Evidence |
|-----|-------------|--------------|
| ADV_ARC | Security architecture | THREAT_MODEL.md |
| ADV_FSP | Functional specification | API documentation |
| ALC_CMC | Configuration management | Git, semantic versioning |
| ALC_CMS | CM scope | Cargo.lock, reproducible |
| ATE_COV | Test coverage | cargo test, fuzz |
| AVA_VAN | Vulnerability analysis | Security audit, fuzz |

---

## Known Limitations and Roadmap

### Current Limitations

| Limitation | Standard Impact | Current Mitigation | Future Plan |
|------------|-----------------|-------------------|-------------|
| Software-only keys (no HSM) | IEC 62443 SL-C = 2 max | File permissions, zeroization | HSM in `platform/` module |
| No OCSP/CRL | ISO 21434 minimal | Fulcio 10-min certs | Document as accepted risk |
| ureq cert pinning limitation | Defense in depth | Pins defined, partial enforcement | Track ureq #1087 |
| Reproducible builds in progress | SLSA 3 | Bazel hermetic builds | Q2 2026 |

### Roadmap

| Quarter | Milestone | Impact |
|---------|-----------|--------|
| Q1 2026 | Complete TARA documentation | Audit-ready evidence package |
| Q2 2026 | HSM integration | Enable SL-C = 3 claims |
| Q3 2026 | Reproducible builds | SLSA 3 compliance |
| Q4 2026 | Third-party security audit | Certification preparation |

**Note**: This roadmap is for WSC component improvements. System integrators must maintain their own compliance roadmaps.

---

## Audit Trail Requirements

### What Must Be Logged

For TARA compliance, the following events should be logged:

1. **Signing Operations**
   - Timestamp
   - Signer identity (OIDC subject)
   - Module hash
   - Key ID used
   - Rekor entry UUID

2. **Verification Operations**
   - Timestamp
   - Module hash
   - Verification result
   - Public key used

3. **Key Management**
   - Key generation
   - Key import/export
   - Key deletion

### Log Format (Structured)

```json
{
  "timestamp": "2026-01-04T12:00:00Z",
  "event": "sign",
  "module_hash": "sha256:abc123...",
  "identity": "user@example.com",
  "key_id": "def456...",
  "rekor_uuid": "108e9186e8c5677a..."
}
```

---

## Certification Checklist

### Pre-Certification

- [ ] Complete threat model review
- [ ] Penetration testing complete
- [ ] Fuzz testing coverage >80%
- [ ] Security audit findings resolved
- [ ] Documentation complete

### Documentation Required

- [x] THREAT_MODEL.md
- [x] TARA_COMPLIANCE.md
- [x] KEY_LIFECYCLE.md
- [x] INCIDENT_RESPONSE.md
- [ ] Security architecture diagram
- [ ] Test coverage report

### Technical Requirements

- [x] Constant-time crypto operations
- [x] Memory zeroization
- [x] Overflow checks in release
- [x] Certificate pinning
- [ ] HSM integration
- [ ] OCSP stapling

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-04 | WSC Team | Initial compliance mapping |
| 1.1 | 2026-01-06 | WSC Team | Clarified component vs system scope, fixed SL claims, added cross-references |
