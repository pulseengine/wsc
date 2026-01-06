# WSC Integration Guidance for TARA Compliance

This document helps system integrators incorporate WSC into their TARA (Threat Analysis and Risk Assessment) processes for ISO/SAE 21434 (automotive) and IEC 62443 (industrial) compliance.

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Date | 2026-01-06 |
| Classification | Public |
| Audience | System integrators, security architects |

---

## Understanding WSC's Role

### What WSC Provides

WSC is a **cryptographic signing and verification component**. It provides:

| Capability | Description |
|------------|-------------|
| Module Integrity | Ed25519 signatures ensure WASM modules haven't been tampered with |
| Identity Binding | Keyless signing binds signatures to OIDC identities |
| Transparency | Rekor log provides immutable audit trail |
| Offline Verification | Airgapped mode for disconnected devices |
| Provenance | SLSA-compliant supply chain attestation |

### What WSC Does NOT Provide

WSC is a **component**, not a complete security solution:

| Not Provided | Your Responsibility |
|--------------|---------------------|
| System-level TARA | You perform TARA on your ITEM |
| Secure boot | Integrate WSC into your boot chain |
| Runtime protection | Use WASM runtime sandboxing |
| HSM integration | Enable via `platform/` module when available |
| Network security | Configure TLS, firewall rules |

---

## Integration Workflow

### Step 1: Identify Your ITEM

Per ISO/SAE 21434, your ITEM is the vehicle system or component being assessed.

**Examples:**
- Vehicle OTA Update ECU
- Industrial PLC firmware loader
- IoT gateway update service
- Container orchestration node

**Document in your TARA:**
```
Item: [Your System Name]
└── Component: WSC (WebAssembly Signature Component)
    └── Function: Module signing and verification
```

### Step 2: Map WSC to Your Architecture

Identify where WSC sits in your trust boundaries:

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR SYSTEM ITEM                          │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                   Build/CI Pipeline                      │ │
│  │  ┌─────────────┐    ┌─────────────┐                     │ │
│  │  │ Source Code │───►│ WSC Sign    │───► Signed Module   │ │
│  │  └─────────────┘    └─────────────┘                     │ │
│  └─────────────────────────────────────────────────────────┘ │
│           ─────────────── Trust Boundary 1 ───────────────   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                   Distribution                           │ │
│  │  ┌─────────────┐    ┌─────────────┐                     │ │
│  │  │ Module Repo │◄───│ CDN/Update  │                     │ │
│  │  └─────────────┘    └─────────────┘                     │ │
│  └─────────────────────────────────────────────────────────┘ │
│           ─────────────── Trust Boundary 2 ───────────────   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                   Target Device                          │ │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │ │
│  │  │ WSC Verify  │───►│ WASM Runtime│───►│ Application │  │ │
│  │  └─────────────┘    └─────────────┘    └─────────────┘  │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Step 3: Reference WSC Evidence

Include WSC documentation as evidence in your TARA work products:

| Your Work Product | WSC Evidence to Reference |
|-------------------|---------------------------|
| Asset Identification | `docs/security/ASSET_INVENTORY.md` |
| Threat Scenarios | `docs/THREAT_MODEL.md` (STRIDE analysis) |
| Risk Assessment | `docs/security/RISK_ASSESSMENT.md` |
| Security Claims | `docs/security/COMPONENT_SECURITY_CLAIMS.md` |
| Key Management | `docs/KEY_LIFECYCLE.md` |
| Incident Response | `docs/INCIDENT_RESPONSE.md` |

**Example TARA Entry:**
```
Threat: T-42 - Unsigned firmware injection
Asset: ECU Firmware Module
Attack Vector: Compromise update channel, inject malicious module
Control: WSC signature verification
Evidence: WSC RISK_ASSESSMENT.md TS-03 (Module Tampering)
Residual Risk: Low (WSC cryptographically prevents tampering)
```

### Step 4: Configure Security Level

WSC supports IEC 62443 Security Levels 1-2 natively, with SL3 requiring HSM:

| Your Target SL | WSC Configuration | Additional Requirements |
|----------------|-------------------|------------------------|
| SL 1 | Default configuration | None |
| SL 2 | Enable cert pinning, secure file permissions | Verify 0600 on key files |
| SL 3 | Enable HSM backend | Configure `platform/` module, HSM hardware |
| SL 4 | Not supported by WSC alone | External TEE, secure boot chain |

**SL 3 Configuration Example:**
```rust
// Future: When HSM integration is complete
use wsc::platform::HsmBackend;

let hsm = HsmBackend::tpm2()?;
let sk = hsm.load_key("wsc-signing-key")?;
let signed = sk.sign(module, Some(&key_id))?;
```

### Step 5: Include in Incident Response

Your incident response plan should include WSC-specific scenarios:

| Scenario | Your Actions | Reference |
|----------|--------------|-----------|
| Signing key compromise | See WSC INC-1 procedure | `INCIDENT_RESPONSE.md` |
| Malicious signed module | Identify signer, revoke key | `INCIDENT_RESPONSE.md` |
| Sigstore outage | Switch to key-based signing | `INCIDENT_RESPONSE.md` |
| WSC vulnerability (CVE) | Update WSC, verify modules | `INCIDENT_RESPONSE.md` |

---

## Security Level Capability Statement

### Official Claim

**WSC Component Security Level (SL-C) = 2**

WSC provides security controls sufficient for IEC 62443 Security Level 2:
- Software cryptographic operations (Ed25519, SHA-256)
- Secure file permissions (0600 for secret keys)
- Memory zeroization for key material
- Certificate pinning for Sigstore endpoints
- Constant-time cryptographic comparisons

### SL 3 Path

Achieving SL-3 with WSC requires:

1. **HSM Integration** (in development)
   - Hardware-protected key storage
   - Key operations in secure enclave

2. **Secure Boot Chain** (your responsibility)
   - Verified WSC binary loading
   - Attestation of runtime environment

3. **Additional Hardening** (your responsibility)
   - Locked memory for sensitive operations
   - Anti-tamper monitoring

---

## TARA Work Product Templates

### Template: Asset Entry for WSC Keys

```markdown
## Asset: WSC Signing Key

| Property | Value |
|----------|-------|
| Asset ID | CRYPTO-001 |
| Type | Ed25519 Secret Key |
| Owner | [Your Team] |
| Location | Build server, `/secure/keys/wsc-sign.sec` |
| Confidentiality | Critical |
| Integrity | Critical |
| Availability | High |
| Protection | File permissions (0600), zeroization |
| Backup | [Your backup procedure] |
```

### Template: Threat Scenario Using WSC

```markdown
## Threat: TS-042 - Update Channel Compromise

| Field | Value |
|-------|-------|
| Threat ID | TS-042 |
| Asset | WASM Application Module |
| Attack Goal | Execute malicious code on target device |
| Attack Vector | MitM on update channel, inject modified module |

### Attack Path
1. Attacker gains position on network path
2. Intercepts legitimate module download
3. Modifies module to include malicious code
4. Delivers modified module to target

### Controls
| Control | Type | Effectiveness |
|---------|------|---------------|
| TLS for download | Preventive | High (but not if CA compromised) |
| **WSC Signature Verification** | Detective/Preventive | **Critical** |
| Runtime sandboxing | Mitigating | Medium |

### Residual Risk Assessment
With WSC verification: **Negligible**
- Modified module fails SHA-256 hash verification
- Attack is cryptographically infeasible
- Reference: WSC RISK_ASSESSMENT.md TS-03
```

### Template: Cybersecurity Requirement

```markdown
## Requirement: REQ-SEC-015 - Module Integrity Verification

| Field | Value |
|-------|-------|
| Requirement ID | REQ-SEC-015 |
| Title | WASM Module Signature Verification |
| Priority | Critical |
| Standard | ISO/SAE 21434 CR-03 |

### Description
All WASM modules loaded by the system MUST be verified against
a trusted signature before execution.

### Implementation
- Use WSC `PublicKey::verify()` before module instantiation
- Reject modules with invalid or missing signatures
- Log verification results to audit trail

### Verification Method
- Unit tests for signature verification
- Integration test with tampered modules
- Fuzz testing of verification path

### Evidence
- WSC library test suite passing
- Integration test results
- Fuzz testing coverage report
```

---

## Common Integration Patterns

### Pattern 1: Build-Time Signing

```
┌────────────┐    ┌────────────┐    ┌────────────┐
│   Build    │───►│ WSC Sign   │───►│  Publish   │
│   System   │    │ (keyless)  │    │  Artifact  │
└────────────┘    └────────────┘    └────────────┘
                        │
                        ▼
                  ┌────────────┐
                  │   Rekor    │ (Transparency Log)
                  └────────────┘
```

**Use Case**: CI/CD pipeline with GitHub Actions, GitLab CI
**WSC Mode**: Keyless signing with OIDC
**Benefit**: No long-lived keys to manage

### Pattern 2: Airgapped Device Verification

```
┌────────────┐         ┌────────────┐         ┌────────────┐
│ Provision  │────────►│ Trust      │────────►│  Device    │
│  Station   │         │ Bundle     │         │ (offline)  │
└────────────┘         └────────────┘         └────────────┘
                                                    │
                                              ┌─────┴─────┐
                                              │ WSC       │
                                              │ Airgapped │
                                              │ Verify    │
                                              └───────────┘
```

**Use Case**: Automotive ECU, industrial PLC, embedded IoT
**WSC Mode**: Airgapped verification with pre-provisioned trust bundle
**Benefit**: No network required at runtime

### Pattern 3: Multi-Stage Supply Chain

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ Vendor A │───►│ Vendor B │───►│ OEM      │───►│ Device   │
│  Sign    │    │  Sign    │    │  Sign    │    │ Verify   │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
     │               │               │
     ▼               ▼               ▼
┌────────────────────────────────────────────────────────────┐
│                    Multi-Signature Chain                    │
│           (All signatures verified at device)               │
└────────────────────────────────────────────────────────────┘
```

**Use Case**: Automotive supply chain, tiered manufacturing
**WSC Mode**: Multi-signature with composition tracking
**Benefit**: Full provenance from source to deployment

---

## Checklist: WSC Integration for TARA

### Pre-Integration

- [ ] Identify your ITEM and scope
- [ ] Map WSC to your architecture diagram
- [ ] Determine required Security Level (SL-T)
- [ ] Review WSC security documentation

### Asset Inventory

- [ ] Add WSC assets to your asset inventory
- [ ] Assign CIA ratings for your context
- [ ] Document key storage locations

### Threat Analysis

- [ ] Reference WSC STRIDE analysis
- [ ] Map WSC threats to your threat scenarios
- [ ] Identify any additional threats from integration

### Risk Assessment

- [ ] Reference WSC AF ratings
- [ ] Assess impact in YOUR system context
- [ ] Document risk treatment decisions
- [ ] Assign residual risk acceptance

### Implementation

- [ ] Configure WSC for your Security Level
- [ ] Integrate verification into runtime
- [ ] Set up key management procedures
- [ ] Configure audit logging

### Verification

- [ ] Test signature verification path
- [ ] Test rejection of unsigned/invalid modules
- [ ] Verify key rotation procedure
- [ ] Conduct penetration testing

### Incident Response

- [ ] Include WSC scenarios in IR plan
- [ ] Test key compromise procedure
- [ ] Establish communication channels

---

## Frequently Asked Questions

### Q: Can I claim my system is "TARA compliant" because I use WSC?

**No.** WSC provides component-level security evidence. TARA is performed on your ITEM (vehicle, ECU, system). You must perform your own TARA and reference WSC evidence as supporting documentation.

### Q: What Security Level can I claim with WSC?

WSC component security level is SL-C = 2. Your system security level (SL-T) depends on:
- All components meeting the target SL
- System-level security architecture
- Operational security procedures

### Q: Do I need Sigstore for ISO 21434 compliance?

No. Key-based signing is sufficient. Keyless signing adds:
- Non-repudiation via Rekor transparency log
- Identity binding without key management
- Useful for CI/CD environments

### Q: How do I handle WSC updates in a certified system?

1. Evaluate the update for security impact
2. Regression test verification functionality
3. Update your TARA if risk profile changes
4. Document the change in your configuration management

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-06 | WSC Team | Initial integration guidance |
