# WSC Component Threat Analysis (STRIDE)

This document provides a **component-level** threat analysis of the WebAssembly Signature Component (WSC) using the STRIDE methodology.

> **Important Clarification**: This is NOT a system-level TARA (Threat Analysis and Risk Assessment). WSC is a cryptographic component that cannot perform TARA in isolation. System integrators must:
> 1. Perform TARA on their ITEM (vehicle ECU, IoT device, etc.)
> 2. Reference this document as evidence for the WSC component
> 3. See `docs/security/INTEGRATION_GUIDANCE.md` for integration help
> 4. See `docs/security/RISK_ASSESSMENT.md` for quantified risk ratings

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.1 |
| Date | 2026-01-06 |
| Status | Active |
| Classification | Public |
| Review Cycle | Quarterly |
| Scope | Component-level analysis only |

## System Overview

WSC is a WebAssembly module signing and verification toolkit that provides:

1. **Ed25519 Signature Operations** - Sign and verify WASM modules
2. **Keyless (Ephemeral) Signing** - Sigstore integration via Fulcio/Rekor
3. **Multi-Signature Support** - Multiple signers on single module
4. **Certificate Provisioning** - X.509 certificate issuance for devices
5. **Provenance/SBOM Embedding** - SLSA compliance support

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                        Build Environment                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │ Source Code │───►│  WSC CLI    │───►│ Signed WASM Module  │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
│                            │                      │              │
│                   Secret Key (TB1)        Signature Data         │
└─────────────────────────────────────────────────────────────────┘
                             │
        ─────────────────────┼───────────────────────
        TRUST BOUNDARY 1     │  (Key Material)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Sigstore Infrastructure                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │   Fulcio    │    │   Rekor     │    │   OIDC Provider     │  │
│  │  (Cert CA)  │    │(Trans. Log) │    │  (GitHub/Google)    │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
        ─────────────────────┼───────────────────────
        TRUST BOUNDARY 2     │  (Network/TLS)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Runtime Environment                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │WASM Runtime │◄───│ Verifier    │◄───│  Public Key Store   │  │
│  │ (wasmtime)  │    │   (wsc)     │    │  (Trust Bundle)     │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## STRIDE Threat Analysis

### S - Spoofing

#### S1: Key Impersonation
| Field | Value |
|-------|-------|
| Threat | Attacker obtains/guesses private key and signs malicious modules |
| Assets | Ed25519 secret keys, OIDC tokens |
| Likelihood | Low (Ed25519 has 128-bit security) |
| Impact | Critical (complete trust compromise) |
| Mitigations | - Key stored in secure locations with 0600 permissions |
|             | - Zeroization of key material on drop |
|             | - Support for HSM/TEE key storage (roadmap) |
| Residual Risk | Low |

#### S2: Certificate Authority Compromise
| Field | Value |
|-------|-------|
| Threat | Fulcio CA issues rogue certificates to attacker |
| Assets | Certificate chain, identity binding |
| Likelihood | Very Low (Sigstore has SCT monitoring) |
| Impact | High (attacker can sign as any identity) |
| Mitigations | - Certificate pinning enforced for Fulcio/Rekor |
|             | - Rekor transparency log provides audit trail |
|             | - Short-lived certificates (10 min validity) |
| Residual Risk | Very Low |

#### S3: OIDC Token Theft
| Field | Value |
|-------|-------|
| Threat | Attacker steals OIDC token from CI environment |
| Assets | OIDC identity token |
| Likelihood | Medium (CI secrets can leak) |
| Impact | Medium (can sign until token expires) |
| Mitigations | - Tokens zeroized after use (Issue #11) |
|             | - Token lifetime typically <10 minutes |
|             | - Rekor provides non-repudiation |
| Residual Risk | Low |

### T - Tampering

#### T1: Module Modification After Signing
| Field | Value |
|-------|-------|
| Threat | Attacker modifies signed WASM module |
| Assets | Signed module content |
| Likelihood | High (if attacker has file access) |
| Impact | None (signature verification fails) |
| Mitigations | - SHA-256 hash of all sections included in signature |
|             | - Any byte change invalidates signature |
| Residual Risk | None |

#### T2: Signature Section Manipulation
| Field | Value |
|-------|-------|
| Threat | Attacker modifies signature section to substitute signature |
| Assets | Signature section content |
| Likelihood | Medium |
| Impact | None (verification uses public key binding) |
| Mitigations | - Signature binds to specific public key |
|             | - Key ID allows explicit key matching |
| Residual Risk | None |

#### T3: Rollback Attack
| Field | Value |
|-------|-------|
| Threat | Attacker substitutes newer module with older signed version |
| Assets | Module version integrity |
| Likelihood | Medium |
| Impact | Medium (vulnerable code executed) |
| Mitigations | - Provenance embedding includes version info |
|             | - Composition manifest tracks dependencies |
|             | - Airgapped verifier supports rollback detection |
| Residual Risk | Low (with provenance verification) |

### R - Repudiation

#### R1: Signer Denies Signing
| Field | Value |
|-------|-------|
| Threat | Legitimate signer claims they did not sign module |
| Assets | Audit trail, accountability |
| Likelihood | Low |
| Impact | Medium (legal/compliance issues) |
| Mitigations | - Rekor transparency log provides immutable record |
|             | - Certificate chain binds to OIDC identity |
|             | - Merkle tree inclusion proof |
| Residual Risk | Very Low |

#### R2: Timestamp Disputes
| Field | Value |
|-------|-------|
| Threat | Dispute over when signing occurred |
| Assets | Temporal integrity |
| Likelihood | Low |
| Impact | Low |
| Mitigations | - Rekor provides trusted timestamp |
|             | - SCT (Signed Certificate Timestamp) from Fulcio |
| Residual Risk | Very Low |

### I - Information Disclosure

#### I1: Key Material Leakage
| Field | Value |
|-------|-------|
| Threat | Secret key leaked via memory dump, swap, or logs |
| Assets | Ed25519 secret keys |
| Likelihood | Low |
| Impact | Critical |
| Mitigations | - Zeroization on drop (zeroize crate) |
|             | - #![forbid(unsafe_code)] prevents memory bugs |
|             | - Secure file permissions (0600) |
|             | - No key material in logs (Issue #9) |
| Residual Risk | Very Low |

#### I2: Timing Side Channels
| Field | Value |
|-------|-------|
| Threat | Attacker extracts key info via timing analysis |
| Assets | Cryptographic secrets |
| Likelihood | Low (requires local access) |
| Impact | High |
| Mitigations | - Constant-time comparison (ct_codecs) |
|             | - ed25519-compact uses constant-time operations |
| Residual Risk | Very Low |

#### I3: Certificate Chain Disclosure
| Field | Value |
|-------|-------|
| Threat | Attacker learns identity from certificate |
| Assets | Signer identity/email |
| Likelihood | High (certificates are public) |
| Impact | Low (by design, not a secret) |
| Mitigations | - This is expected behavior for accountability |
| Residual Risk | N/A (accepted) |

### D - Denial of Service

#### D1: Resource Exhaustion
| Field | Value |
|-------|-------|
| Threat | Malformed input causes memory exhaustion |
| Assets | System availability |
| Likelihood | Medium |
| Impact | Medium |
| Mitigations | - 16 MB allocation limits |
|             | - Bounded varint parsing |
|             | - Maximum section counts enforced |
|             | - Fuzz testing (6 targets) |
| Residual Risk | Low |

#### D2: Infinite Loop/Hang
| Field | Value |
|-------|-------|
| Threat | Crafted input causes infinite processing |
| Assets | System availability |
| Likelihood | Low |
| Impact | Medium |
| Mitigations | - Bounded iteration in parsers |
|             | - No recursion in critical paths |
|             | - Fuzz testing for hangs |
| Residual Risk | Very Low |

#### D3: Network Resource Exhaustion
| Field | Value |
|-------|-------|
| Threat | Attacker floods Fulcio/Rekor requests |
| Assets | Sigstore service availability |
| Likelihood | Low (rate limits exist) |
| Impact | Medium (signing unavailable) |
| Mitigations | - Sigstore has rate limiting |
|             | - Fallback to traditional signing |
| Residual Risk | Low |

### E - Elevation of Privilege

#### E1: Code Execution via Parser Bug
| Field | Value |
|-------|-------|
| Threat | Crafted module triggers code execution |
| Assets | System integrity |
| Likelihood | Very Low |
| Impact | Critical |
| Mitigations | - #![forbid(unsafe_code)] |
|             | - Rust memory safety |
|             | - Comprehensive fuzz testing |
|             | - Bounds checking on all reads |
| Residual Risk | Very Low |

#### E2: Privilege Escalation via File Permissions
| Field | Value |
|-------|-------|
| Threat | Attacker exploits insecure key file permissions |
| Assets | Key material |
| Likelihood | Low |
| Impact | Critical |
| Mitigations | - Keys written with 0600 permissions (Issue #10) |
|             | - Warnings on insecure existing files |
| Residual Risk | Very Low |

---

## Attack Surface Summary

| Component | Attack Surface | Risk Level |
|-----------|---------------|------------|
| WASM Parser | Malformed sections, oversized data | Low |
| Signature Verification | Timing attacks, algorithm weaknesses | Very Low |
| Key Management | File permissions, memory residue | Low |
| Keyless Signing | OIDC token handling, TLS | Low |
| Certificate Pinning | MitM during updates | Very Low |
| Provenance/SBOM | Substitution attacks | Low |

---

## Security Controls Summary

### Cryptographic Controls
- Ed25519 signatures (128-bit security)
- SHA-256 hashing
- Constant-time operations
- Zeroization of sensitive data

### Access Controls
- Secure file permissions (0600)
- Key ID matching
- Certificate chain validation
- Certificate pinning for Sigstore

### Audit Controls
- Rekor transparency log
- Merkle tree inclusion proofs
- Provenance embedding
- SBOM generation

### Availability Controls
- Resource limits (16 MB)
- Bounded parsing
- Fuzz testing
- Fallback mechanisms

---

## Compliance Evidence

This STRIDE analysis provides evidence for the following standards. Note that full compliance requires system-level TARA by the integrator.

| Requirement | Standard | WSC Control | Evidence Type |
|-------------|----------|-------------|---------------|
| Cryptographic strength | ISO 21434 | Ed25519 (128-bit), SHA-256 | Component claim |
| Key management | IEC 62443 | Secure storage, zeroization | Component claim |
| Audit logging | ISO 27001 | Rekor integration | Component claim |
| Secure development | SLSA L2+ | Provenance, reproducible builds | Build evidence |
| Memory safety | MISRA C++ | Rust #![forbid(unsafe_code)] | Design evidence |

For quantified risk assessment with ISO 21434 Attack Feasibility ratings, see `docs/security/RISK_ASSESSMENT.md`.

---

## Residual Risks

1. **HSM Integration Incomplete**: Software key storage is less secure than hardware
   - Mitigation: HSM support scaffolded, roadmap item

2. **OCSP/CRL Not Implemented**: Certificate revocation relies on short validity
   - Mitigation: Fulcio certificates are 10-minute validity

3. **Swap File Exposure**: Keys in memory could be swapped to disk
   - Mitigation: Use locked memory in production (OS-level)

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-04 | WSC Team | Initial STRIDE analysis |
| 1.1 | 2026-01-06 | WSC Team | Clarified component vs system scope, added TARA integration guidance |
