# WSC Incident Response Runbook

This document provides step-by-step procedures for responding to security incidents involving WSC deployments.

> **Note for System Integrators**: This runbook covers WSC component incidents. You must integrate these procedures into your system-level incident response plan.

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.1 |
| Date | 2026-01-06 |
| Classification | Public |
| Review Cycle | Annually |

---

## RACI Matrix

For each incident type, responsibilities are assigned using RACI:
- **R**esponsible: Does the work
- **A**ccountable: Ultimately answerable
- **C**onsulted: Provides input
- **I**nformed: Kept up to date

### WSC Project Incidents

| Activity | WSC Maintainers | System Integrator | End User |
|----------|-----------------|-------------------|----------|
| Detect WSC vulnerability | R/A | C | I |
| Patch WSC code | R/A | I | I |
| Release security advisory | R/A | I | I |
| Update WSC dependency | I | R/A | I |
| Regression test | I | R/A | I |

### Deployment Incidents

| Activity | WSC Maintainers | System Integrator | End User |
|----------|-----------------|-------------------|----------|
| Detect signing key compromise | C | R/A | I |
| Revoke compromised key | C | R/A | I |
| Generate new key | I | R/A | I |
| Re-sign affected modules | I | R/A | I |
| Update trust bundles | I | R/A | I |
| Notify downstream users | I | R/A | I |

### Sigstore Incidents

| Activity | WSC Maintainers | Sigstore Team | System Integrator |
|----------|-----------------|---------------|-------------------|
| Detect Sigstore compromise | I | R/A | C |
| Publish advisory | I | R/A | I |
| Switch to offline mode | I | I | R/A |
| Audit affected signatures | C | C | R/A |

---

## Incident Classification

### Severity Levels

| Level | Description | Response Time | Examples |
|-------|-------------|---------------|----------|
| Critical | Active compromise, key leaked | Immediate | Private key on public repo |
| High | Suspected compromise | < 4 hours | Unauthorized signatures detected |
| Medium | Vulnerability discovered | < 24 hours | New CVE affecting dependencies |
| Low | Policy violation | < 1 week | Key file permission issues |

---

## Incident Types

### INC-1: Private Key Compromise

**Indicators:**
- Key file found in public location
- Unauthorized signatures appearing
- Key file permissions changed
- Suspicious signing activity in logs

**Immediate Actions (First 30 minutes):**

1. **Isolate the key**
   ```bash
   # Move key to secure offline location
   mv ~/.wsc/keys/compromised.sec /secure/offline/location/

   # Change permissions to prevent any use
   chmod 000 /secure/offline/location/compromised.sec
   ```

2. **Identify scope**
   ```bash
   # Find all modules signed with this key
   find /path/to/modules -name "*.wasm" -exec wsc info {} \; | grep -l "KEY_ID"
   ```

3. **Notify stakeholders**
   - Security team
   - Affected downstream users
   - If using Sigstore: No action needed (short-lived certs)

**Recovery Actions (Within 24 hours):**

4. **Generate replacement key**
   ```bash
   wsc keygen -p new-signing-key
   ```

5. **Re-sign affected modules**
   ```bash
   for module in $(cat affected-modules.txt); do
       wsc sign --secretkey new-signing-key.sec "$module"
   done
   ```

6. **Update trust bundles**
   - Add new public key to all verifiers
   - Consider grace period with both keys
   - Eventually remove compromised key

7. **Forensic analysis**
   - How was key accessed?
   - What was signed with it?
   - Timeline of compromise

---

### INC-2: Malicious Module Detected

**Indicators:**
- Module passes verification but contains malware
- Legitimate signer's identity was compromised
- Insider threat scenario

**Immediate Actions:**

1. **Quarantine the module**
   ```bash
   # Move to quarantine, preserve for analysis
   mv malicious.wasm /quarantine/$(date +%Y%m%d)_malicious.wasm
   sha256sum /quarantine/*.wasm > /quarantine/hashes.txt
   ```

2. **Extract signature information**
   ```bash
   wsc info quarantined.wasm > incident_evidence.txt
   ```

3. **Check Rekor for signing record**
   ```bash
   # If keyless signed, get the transparency log entry
   rekor-cli get --uuid <uuid-from-signature>
   ```

4. **Block the signing identity**
   - If OIDC: Contact identity provider
   - If key-based: Add public key to blocklist

**Recovery:**

5. **Notify affected parties**
   - Users who downloaded the module
   - Platform/registry operators
   - CERT if applicable

6. **Publish advisory**
   - Module hash
   - Signing identity
   - Impact assessment
   - Remediation steps

---

### INC-3: Sigstore Service Compromise

**Indicators:**
- Sigstore announces security incident
- Rogue certificates observed
- Rekor entries appear fraudulent

**Immediate Actions:**

1. **Switch to offline verification**
   ```bash
   # Disable online verification
   export WSC_OFFLINE=1

   # Use pre-distributed trust bundle
   wsc verify --trust-bundle /path/to/bundle.json module.wasm
   ```

2. **Audit recent signatures**
   - Review all modules signed during incident window
   - Cross-reference with expected signers

3. **Monitor Sigstore advisories**
   - https://sigstore.dev/security
   - Sigstore Slack #security channel

**Recovery:**

4. **Wait for Sigstore all-clear**
5. **Re-verify affected modules if needed**
6. **Update certificate pins if root rotated**

---

### INC-4: Dependency Vulnerability (CVE)

**Indicators:**
- CVE announced in WSC dependency
- Security advisory from crates.io
- Automated scanner alert

**Assessment:**

1. **Check if WSC is affected**
   ```bash
   # Review dependency tree
   cargo tree -p affected-crate

   # Check if vulnerable code path is used
   cargo audit
   ```

2. **Severity assessment**
   - Is the vulnerable code reachable?
   - What input is required to trigger?
   - Is there a workaround?

**Mitigation:**

3. **Update dependency**
   ```bash
   cargo update -p affected-crate
   cargo test
   cargo audit
   ```

4. **Release patch version**
   ```bash
   # Bump patch version
   # Update CHANGELOG
   # Tag and release
   ```

5. **Notify users**
   - GitHub Security Advisory
   - Release notes
   - Direct notification for critical issues

---

## Communication Templates

### Key Compromise Notification

```
Subject: [SECURITY] WSC Signing Key Compromise - Action Required

Summary: A signing key used for WSC modules has been compromised.

Affected Key ID: [KEY_ID]
Compromise Date: [DATE] (estimated)
Discovery Date: [DATE]

Impact:
- Modules signed with this key after [DATE] should not be trusted
- Modules signed before [DATE] are believed to be unaffected

Required Actions:
1. Update your trust bundle to remove key [KEY_ID]
2. Re-verify any modules signed with this key
3. Contact security@example.com if you observe suspicious modules

New Key ID: [NEW_KEY_ID]
New Public Key: [URL or attached]

Timeline:
- [DATE]: Compromise discovered
- [DATE]: Key revoked
- [DATE]: New key generated
- [DATE]: Affected modules re-signed

We apologize for any inconvenience.
```

### Vulnerability Disclosure

```
Subject: [SECURITY] WSC Security Advisory - [CVE-YYYY-XXXXX]

Severity: [CRITICAL/HIGH/MEDIUM/LOW]
CVE: CVE-YYYY-XXXXX
Affected Versions: X.Y.Z - A.B.C
Fixed Version: X.Y.Z

Description:
[Brief description of vulnerability]

Impact:
[What an attacker could do]

Mitigation:
1. Upgrade to version X.Y.Z or later
2. [Alternative workaround if available]

Credit:
[Researcher/finder]

Timeline:
- [DATE]: Vulnerability reported
- [DATE]: Fix developed
- [DATE]: Coordinated disclosure
```

---

## Post-Incident Actions

### Required for All Incidents

1. **Document timeline**
   - When discovered
   - Actions taken
   - Resolution time

2. **Root cause analysis**
   - What allowed this to happen?
   - What controls failed?

3. **Update procedures**
   - What would have prevented this?
   - What would have detected it sooner?

4. **Update threat model**
   - Add new threat if applicable
   - Update risk ratings

### Metrics to Track

| Metric | Target |
|--------|--------|
| Time to detect | < 24 hours |
| Time to contain | < 4 hours |
| Time to recover | < 48 hours |
| Post-incident review | Within 1 week |

---

## Emergency Contacts

### WSC Project

| Role | Contact |
|------|---------|
| Security Reports | File issue at https://github.com/pulseengine/wsc/security |
| General Issues | https://github.com/pulseengine/wsc/issues |

### External Services

| Service | Contact | When to Use |
|---------|---------|-------------|
| Sigstore Security | security@sigstore.dev | Fulcio/Rekor incidents |
| GitHub Security | security@github.com | GitHub Actions token issues |

### System Integrator (Fill In Your Contacts)

| Role | Contact | Notes |
|------|---------|-------|
| Security Lead | [Your security team] | First escalation point |
| On-Call Engineer | [Your on-call] | For critical severity |
| Legal/Compliance | [Your legal team] | For data breach notification |
| Communications | [Your PR team] | For public disclosure |

**Note**: System integrators must fill in their own contacts above.

---

## Appendix: Useful Commands

### Key Operations

```bash
# List all keys
ls -la ~/.wsc/keys/

# Check key permissions
stat -c '%a %n' ~/.wsc/keys/*.sec

# Verify key file hasn't been modified
sha256sum ~/.wsc/keys/*.sec > key_hashes.txt
diff key_hashes.txt stored_hashes.txt

# Securely delete key
shred -vfz -n 5 compromised.sec
```

### Module Analysis

```bash
# Get signature info
wsc info signed.wasm

# Verify with specific key
wsc verify --publickey trusted.pub signed.wasm

# List all signatures on module
wsc info --signatures signed.wasm

# Extract embedded provenance
wsc info --provenance signed.wasm
```

### Rekor Operations

```bash
# Search by email
rekor-cli search --email signer@example.com

# Search by artifact hash
rekor-cli search --sha sha256:abc123...

# Get entry details
rekor-cli get --uuid 108e9186...

# Verify inclusion proof
rekor-cli verify --artifact signed.wasm --signature sig.bin
```

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-04 | WSC Team | Initial incident response runbook |
| 1.1 | 2026-01-06 | WSC Team | Added RACI matrix, improved contacts section, integrator guidance |
