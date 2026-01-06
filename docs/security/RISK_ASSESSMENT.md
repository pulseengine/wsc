# WSC Risk Assessment

This document provides quantified risk assessment for WSC using ISO/SAE 21434 Attack Feasibility (AF) methodology and explicit risk treatment decisions.

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Date | 2026-01-06 |
| Classification | Public |
| Review Cycle | Quarterly |
| Standard Reference | ISO/SAE 21434 Clauses 15.5-15.9 |

---

## Scope and Limitations

**Important**: This is a *component-level* risk assessment for WSC as a software library. It is NOT a system-level TARA.

System integrators must:
1. Perform their own TARA on their ITEM (vehicle ECU, IoT gateway, etc.)
2. Reference this assessment as evidence for the WSC component
3. Assess how WSC risks affect their overall system risk profile

---

## Attack Feasibility Rating Methodology

Per ISO/SAE 21434 Annex H, attack feasibility is calculated using five factors:

### Factor Scoring

| Factor | Description | Points |
|--------|-------------|--------|
| **Elapsed Time** | Time to identify/develop attack | 0 (≤1 day) to 19 (≥6 months) |
| **Specialist Expertise** | Attacker skill level required | 0 (Layman) to 8 (Expert) |
| **Knowledge of Item** | Target information needed | 0 (Public) to 11 (Critical) |
| **Window of Opportunity** | Access conditions | 0 (Unlimited) to 10 (Difficult) |
| **Equipment** | Attack tools required | 0 (Standard) to 9 (Bespoke) |

### AF Rating Thresholds

| Total Points | AF Rating | Interpretation |
|--------------|-----------|----------------|
| 0-9 | High | Attack is feasible for low-skilled attackers |
| 10-13 | Medium | Attack requires moderate skill/resources |
| 14-19 | Low | Attack requires significant skill/resources |
| 20+ | Very Low | Attack is impractical for most adversaries |

---

## Impact Rating Methodology

Per ISO/SAE 21434, impacts are rated on the SFOP scale:

| Category | Negligible | Moderate | Major | Severe |
|----------|------------|----------|-------|--------|
| **S**afety | No injury | Minor injury | Serious injury | Life-threatening |
| **F**inancial | <$1K | $1K-$100K | $100K-$1M | >$1M |
| **O**perational | No disruption | Minor disruption | Significant disruption | Complete failure |
| **P**rivacy | No PII | Limited PII | Bulk PII | Sensitive PII |

---

## Risk Determination Matrix

| AF Rating | Negligible Impact | Moderate Impact | Major Impact | Severe Impact |
|-----------|-------------------|-----------------|--------------|---------------|
| **High** | Low Risk | Medium Risk | High Risk | Critical Risk |
| **Medium** | Low Risk | Medium Risk | High Risk | High Risk |
| **Low** | Negligible Risk | Low Risk | Medium Risk | High Risk |
| **Very Low** | Negligible Risk | Negligible Risk | Low Risk | Medium Risk |

---

## Threat Scenarios and Risk Assessment

### TS-01: Private Key Theft

| Field | Value |
|-------|-------|
| **Threat ID** | TS-01 |
| **Asset** | KEY-001 (Ed25519 Secret Key) |
| **Attack Goal** | Obtain secret key to sign unauthorized modules |
| **Attack Vector** | File system access, memory dump, insider threat |

#### Attack Feasibility Calculation

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <1 week | 4 | Simple if access is gained |
| Specialist Expertise | Proficient | 4 | Understands file systems, crypto basics |
| Knowledge of Item | Restricted | 7 | Needs to know key location, format |
| Window of Opportunity | Moderate | 4 | Requires system access |
| Equipment | Standard | 0 | Standard file copy tools |
| **Total** | | **19** | |

**AF Rating**: Low (14-19 points)

#### Impact Assessment

| Category | Rating | Rationale |
|----------|--------|-----------|
| Safety | Moderate | Malicious code could cause harm in automotive/industrial |
| Financial | Major | Breach of trust, re-signing cost, reputation damage |
| Operational | Major | Must revoke key, re-sign modules, update verifiers |
| Privacy | Negligible | Keys don't contain PII |

**Impact**: Major (highest category)

#### Risk Determination

| AF Rating | Impact | Risk Level |
|-----------|--------|------------|
| Low | Major | **Medium Risk** |

#### Risk Treatment

| Decision | Rationale |
|----------|-----------|
| **Reduce** | Implement additional controls |

**Controls Applied**:
1. File permissions (0600) - Implemented ✅
2. Zeroization on drop - Implemented ✅
3. HSM support - Roadmap (reduces to Low Risk when complete)
4. Secure key generation - Implemented ✅

---

### TS-02: OIDC Token Theft (Keyless Signing)

| Field | Value |
|-------|-------|
| **Threat ID** | TS-02 |
| **Asset** | CRED-001 (OIDC Token) |
| **Attack Goal** | Steal token to sign as victim's identity |
| **Attack Vector** | CI environment compromise, log exposure |

#### Attack Feasibility Calculation

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | <1 day | 0 | Token expires in ~10 minutes |
| Specialist Expertise | Proficient | 4 | CI/CD knowledge needed |
| Knowledge of Item | Sensitive | 11 | Token format, Sigstore flow |
| Window of Opportunity | Difficult | 10 | Only valid during signing |
| Equipment | Standard | 0 | Standard network tools |
| **Total** | | **25** | |

**AF Rating**: Very Low (20+ points)

#### Impact Assessment

| Category | Rating | Rationale |
|----------|--------|-----------|
| Safety | Moderate | Signed malicious module could cause harm |
| Financial | Moderate | Limited window, Rekor provides audit trail |
| Operational | Moderate | Identity is logged, investigation possible |
| Privacy | Negligible | Token itself not PII |

**Impact**: Moderate

#### Risk Determination

| AF Rating | Impact | Risk Level |
|-----------|--------|------------|
| Very Low | Moderate | **Negligible Risk** |

#### Risk Treatment

| Decision | Rationale |
|----------|-----------|
| **Accept** | Risk is already negligible |

**Why Accept**:
- Token lifetime is ~10 minutes
- Rekor provides immutable audit trail
- Identity is cryptographically bound to signature

---

### TS-03: Module Tampering Post-Signature

| Field | Value |
|-------|-------|
| **Threat ID** | TS-03 |
| **Asset** | WASM-002 (Signed Module) |
| **Attack Goal** | Modify signed module to inject malicious code |
| **Attack Vector** | Transit interception, storage modification |

#### Attack Feasibility Calculation

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | N/A | N/A | Attack fundamentally fails |
| Specialist Expertise | N/A | N/A | - |
| Knowledge of Item | N/A | N/A | - |
| Window of Opportunity | N/A | N/A | - |
| Equipment | N/A | N/A | - |
| **Total** | | **N/A** | |

**AF Rating**: Not Applicable - Attack is cryptographically infeasible

#### Impact Assessment

| Category | Rating | Rationale |
|----------|--------|-----------|
| All | None | Verification fails for tampered modules |

**Impact**: None

#### Risk Determination

| AF Rating | Impact | Risk Level |
|-----------|--------|------------|
| N/A | None | **No Risk** |

#### Risk Treatment

| Decision | Rationale |
|----------|-----------|
| **N/A** | This is a security control, not a risk |

---

### TS-04: Trust Bundle Manipulation

| Field | Value |
|-------|-------|
| **Threat ID** | TS-04 |
| **Asset** | TRUST-002 (Airgapped Trust Bundle) |
| **Attack Goal** | Inject rogue public key to accept malicious modules |
| **Attack Vector** | Compromise provisioning process, file substitution |

#### Attack Feasibility Calculation

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | ≤2 weeks | 7 | Bundle has integrity protection |
| Specialist Expertise | Expert | 8 | Cryptographic understanding needed |
| Knowledge of Item | Critical | 11 | Bundle format, provisioning process |
| Window of Opportunity | Moderate | 4 | During device provisioning |
| Equipment | Specialized | 6 | Provisioning environment access |
| **Total** | | **36** | |

**AF Rating**: Very Low (20+ points)

#### Impact Assessment

| Category | Rating | Rationale |
|----------|--------|-----------|
| Safety | Severe | Complete trust bypass in safety-critical device |
| Financial | Major | Fleet-wide compromise potential |
| Operational | Severe | All verification fails for legitimate modules |
| Privacy | Moderate | Depends on module purpose |

**Impact**: Severe

#### Risk Determination

| AF Rating | Impact | Risk Level |
|-----------|--------|------------|
| Very Low | Severe | **Medium Risk** |

#### Risk Treatment

| Decision | Rationale |
|----------|-----------|
| **Reduce** | Add additional integrity controls |

**Controls Applied**:
1. Bundle is signed - Implemented ✅
2. Secure provisioning guidance - Documented ✅
3. Certificate pinning for updates - Implemented ✅

---

### TS-05: Timing Side-Channel Attack

| Field | Value |
|-------|-------|
| **Threat ID** | TS-05 |
| **Asset** | KEY-001, KEY-003 (Secret Keys) |
| **Attack Goal** | Extract key material via timing analysis |
| **Attack Vector** | Repeated operations with timing measurements |

#### Attack Feasibility Calculation

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | ≥6 months | 19 | Statistical analysis, noise filtering |
| Specialist Expertise | Expert | 8 | Cryptographic side-channel research |
| Knowledge of Item | Sensitive | 11 | Algorithm internals |
| Window of Opportunity | Easy | 1 | Need repeated access to signing |
| Equipment | Specialized | 6 | High-precision timing equipment |
| **Total** | | **45** | |

**AF Rating**: Very Low (20+ points)

#### Impact Assessment

| Category | Rating | Rationale |
|----------|--------|-----------|
| Safety | Major | Key compromise enables malicious signing |
| Financial | Major | Key replacement, re-signing cost |
| Operational | Major | Trust revocation required |
| Privacy | Negligible | Keys don't contain PII |

**Impact**: Major

#### Risk Determination

| AF Rating | Impact | Risk Level |
|-----------|--------|------------|
| Very Low | Major | **Low Risk** |

#### Risk Treatment

| Decision | Rationale |
|----------|-----------|
| **Reduce** | Use constant-time operations |

**Controls Applied**:
1. ct_equal() for cryptographic comparisons - Implemented ✅ (PR #26)
2. ed25519-compact uses constant-time operations - Implemented ✅
3. p256 crate uses constant-time operations - Implemented ✅

---

### TS-06: Certificate Authority Compromise (Fulcio)

| Field | Value |
|-------|-------|
| **Threat ID** | TS-06 |
| **Asset** | CRED-002 (Fulcio Certificate) |
| **Attack Goal** | Issue rogue certificates for any identity |
| **Attack Vector** | Fulcio infrastructure compromise |

#### Attack Feasibility Calculation

| Factor | Value | Points | Rationale |
|--------|-------|--------|-----------|
| Elapsed Time | ≥6 months | 19 | Sigstore security hardening |
| Specialist Expertise | Expert | 8 | Infrastructure security expertise |
| Knowledge of Item | Critical | 11 | Fulcio internals |
| Window of Opportunity | Difficult | 10 | Requires Sigstore infra access |
| Equipment | Bespoke | 9 | Nation-state level resources |
| **Total** | | **57** | |

**AF Rating**: Very Low (20+ points - maximum difficulty)

#### Impact Assessment

| Category | Rating | Rationale |
|----------|--------|-----------|
| Safety | Severe | Arbitrary signing as any identity |
| Financial | Severe | Trust model completely broken |
| Operational | Severe | All keyless signatures suspect |
| Privacy | Moderate | Identity spoofing |

**Impact**: Severe

#### Risk Determination

| AF Rating | Impact | Risk Level |
|-----------|--------|------------|
| Very Low | Severe | **Medium Risk** |

#### Risk Treatment

| Decision | Rationale |
|----------|-----------|
| **Transfer** + **Reduce** | Rely on Sigstore's security + add local controls |

**Controls Applied**:
1. Certificate pinning for Fulcio - Implemented ✅
2. Short-lived certificates (10 min) - Inherent design ✅
3. Rekor transparency log - Detection control ✅
4. Fallback to key-based signing - Implemented ✅

---

## Risk Summary

| Threat | AF Rating | Impact | Risk Level | Treatment | Status |
|--------|-----------|--------|------------|-----------|--------|
| TS-01: Key Theft | Low | Major | Medium | Reduce | Controlled |
| TS-02: Token Theft | Very Low | Moderate | Negligible | Accept | Accepted |
| TS-03: Module Tampering | N/A | None | None | N/A | By Design |
| TS-04: Trust Bundle Manipulation | Very Low | Severe | Medium | Reduce | Controlled |
| TS-05: Timing Attack | Very Low | Major | Low | Reduce | Controlled |
| TS-06: Fulcio Compromise | Very Low | Severe | Medium | Transfer+Reduce | Controlled |

---

## Residual Risks

After applying all controls, the following residual risks remain:

| Risk | Residual Level | Accepted By | Review Date |
|------|----------------|-------------|-------------|
| Key theft (software storage) | Low | [Integrator] | [Quarterly] |
| HSM not yet integrated | Medium | [Integrator] | [Q2 2026] |
| ureq cert pinning limitation | Low | [Integrator] | [Track ureq #1087] |

**Note**: Residual risk acceptance is the responsibility of the system integrator, not WSC.

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-06 | WSC Team | Initial risk assessment per ISO 21434 |
