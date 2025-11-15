# Security Documentation

This document provides comprehensive security information for developers and operators using wsc (WebAssembly Signature Component).

## Table of Contents

- [Overview](#overview)
- [Keyless Signing Security Model](#keyless-signing-security-model)
- [Certificate-Based Signing Security](#certificate-based-signing-security)
- [Security Guarantees](#security-guarantees)
- [Threat Model](#threat-model)
- [Operational Security](#operational-security)
- [Comparison with Other Systems](#comparison-with-other-systems)

---

## Overview

wsc provides two signing approaches, each with distinct security models:

1. **Keyless Signing** - Ephemeral keys with OIDC identity and Rekor transparency log
2. **Certificate-Based Signing** - Long-lived keys with X.509 PKI and hardware security

This document focuses primarily on **keyless signing** security (addressing Issues #4 and #2).

---

## Keyless Signing Security Model

### Architecture Overview

```
┌─────────────┐     ┌──────────────┐     ┌───────────┐
│   CI/CD     │────▶│  OIDC Token  │────▶│  Fulcio   │
│ Environment │     │  (Identity)  │     │  (Certs)  │
└─────────────┘     └──────────────┘     └─────┬─────┘
                                                │
                    ┌───────────────────────────┘
                    │
                    ▼
            ┌───────────────┐
            │  Ephemeral    │
            │  ECDSA P-256  │◀───── Generated on-demand
            │  Private Key  │       Zeroized after use
            └───────┬───────┘
                    │
                    │ Signs
                    ▼
            ┌───────────────┐
            │ WASM Module   │
            │  + Signature  │
            └───────┬───────┘
                    │
                    │ Upload
                    ▼
            ┌───────────────┐
            │  Rekor Log    │◀───── Public transparency
            │ (Timestamp +  │       Inclusion proof
            │  Proof)       │       Checkpoint signature
            └───────────────┘
```

### Ephemeral Key Lifecycle

Keyless signing uses **ephemeral ECDSA P-256 keys** that exist only for the duration of a single signing operation.

#### Phase 1: Key Generation
```rust
// Generated using cryptographically secure random number generator
let signing_key = SigningKey::<p256::NistP256>::random(&mut OsRng);
```

**Security Properties:**
- Generated using OS-provided CSPRNG (`OsRng`)
- 256-bit key strength (128-bit security level)
- Never written to disk
- Never leaves process memory

#### Phase 2: Public Key Extraction
```rust
let verifying_key = signing_key.verifying_key();
let public_key_bytes = verifying_key.to_encoded_point(false);
```

**Security Properties:**
- Public key can be freely shared
- Used for Fulcio certificate request
- Encoded in uncompressed SEC1 format

#### Phase 3: Certificate Issuance (Fulcio)
```rust
let certificate = fulcio.get_certificate(&oidc_token, public_key, &proof)?;
```

**Process:**
1. Prove possession of private key (sign OIDC `sub` claim)
2. Fulcio validates OIDC token
3. Fulcio issues short-lived X.509 certificate (~10 minutes validity)
4. Certificate binds public key to OIDC identity

**Trust Assumptions:**
- OIDC provider correctly authenticates user
- Fulcio CA is trusted and not compromised
- Network connection to Fulcio is secure (TLS)

#### Phase 4: Signing Operation
```rust
let module_hash = Sha256::digest(&module_bytes);
let signature = signing_key.sign_digest(module_hash);
```

**Security Properties:**
- Signs SHA-256 hash of WASM module
- Signature binds to exact module content
- Uses ECDSA with deterministic nonce (RFC 6979)

#### Phase 5: Transparency Log (Rekor)
```rust
let rekor_entry = rekor.upload_entry(&module_hash, &signature, &certificate)?;
```

**Process:**
1. Upload signature + certificate + hash to Rekor
2. Rekor validates and timestamps the entry
3. Returns signed entry timestamp (SET) and inclusion proof
4. Provides public auditability

**Security Properties:**
- Immutable public log (append-only)
- Cryptographic proof of inclusion in log
- Timestamped by trusted timestamping authority
- Enables detection of misissuance or compromise

#### Phase 6: Key Zeroization
```rust
// Automatic when signing_key goes out of scope
// SigningKey's internal SecretKey implements ZeroizeOnDrop
```

**Security Properties:**
- Private key bytes overwritten with zeros
- Happens even on panic/error (Rust Drop guarantee)
- Prevents key recovery from memory dumps
- Mitigates cold boot attacks

**Implementation:** See `src/lib/src/signature/keyless/signer.rs:142-157`

---

### Trust Model

#### What We Trust

1. **OIDC Provider** (e.g., GitHub Actions)
   - Correctly authenticates workflow identity
   - Protects token issuance
   - Provides authentic `sub` and `iss` claims

2. **Fulcio Certificate Authority**
   - Issues certificates only for valid OIDC tokens
   - Properly validates proof of possession
   - Certificate validity period is accurate (~10 min)
   - Root CA private key is secure

3. **Rekor Transparency Log**
   - Accepts and timestamps all entries honestly
   - Provides correct inclusion proofs
   - Signed tree heads (checkpoints) are authentic
   - Log is append-only and immutable

4. **Cryptographic Primitives**
   - ECDSA P-256 is secure (no known practical attacks)
   - SHA-256 is collision-resistant
   - Random number generator is unpredictable
   - Zeroize library correctly clears memory

5. **Rust Language & Libraries**
   - Memory safety prevents use-after-free, buffer overflows
   - Type system prevents many logic errors
   - `p256`, `ecdsa`, `webpki` crates are correctly implemented

#### What We Don't Trust

1. **The Signer's Environment**
   - May be compromised or malicious
   - Ephemeral key only exists during signing
   - No long-lived secrets to steal

2. **Network Infrastructure**
   - TLS protects in transit
   - But assumes HTTPS is properly configured
   - Certificate pinning can be added (Issue #12)

3. **Verification Environment**
   - Verifier must have correct Fulcio root CA
   - Must check Rekor inclusion proof
   - Must validate certificate at correct timestamp

---

## Threat Model

### In-Scope Threats

#### 1. OIDC Token Theft

**Attack:** Adversary steals OIDC token from environment variables.

**Impact:** Can request Fulcio certificate for stolen identity.

**Mitigations:**
- Tokens are single-use with short lifetime (~15 minutes)
- Token zeroized from memory after use (Issue #11 ✅)
- Rekor log provides audit trail of all signatures
- Token theft requires environment access (same as private key theft)

**Residual Risk:** LOW - Token lifetime limits exposure window

#### 2. Ephemeral Key Compromise

**Attack:** Memory dump or debugger extracts private key.

**Impact:** Can forge signatures for the duration of key's lifetime.

**Mitigations:**
- Key exists only during signing operation (<1 second)
- Zeroized immediately after use (Issue #14 ✅)
- Requires attacker to time attack perfectly
- Signature is logged in Rekor (detectable)

**Residual Risk:** VERY LOW - Tiny attack window

#### 3. Man-in-the-Middle (MITM)

**Attack:** Intercept communication with Fulcio/Rekor.

**Impact:** Could steal OIDC token, modify responses.

**Mitigations:**
- TLS encryption for all HTTPS requests
- Fulcio certificate chains to trusted root
- Rekor entries have signed timestamps
- Certificate pinning available (Issue #12 - future)

**Residual Risk:** LOW - Requires TLS compromise

#### 4. Rekor Log Tampering

**Attack:** Modify Rekor log after signature creation.

**Impact:** Could hide evidence of signature or forge timestamps.

**Mitigations:**
- Merkle tree inclusion proofs (Issue #15 ✅)
- Signed tree heads (checkpoints) from Rekor
- Gossip protocol for checkpoint consistency (Sigstore project)
- Multiple monitors can detect tampering

**Residual Risk:** LOW - Cryptographically protected

### Out-of-Scope Threats

#### 1. Sigstore Infrastructure Compromise

**Threat:** Fulcio or Rekor completely compromised.

**Rationale:** If core infrastructure is compromised, system security fails. This is a trust anchor. Mitigation requires infrastructure-level security (HSMs, monitoring, incident response) which is Sigstore's responsibility.

#### 2. Side-Channel Attacks

**Threat:** Timing attacks, power analysis, electromagnetic emanation.

**Rationale:**
- p256 crate uses constant-time operations
- ECDSA nonce is deterministic (RFC 6979), eliminating nonce attacks
- Ephemeral keys reduce exposure window
- Production environments typically not vulnerable to physical side-channels

#### 3. Quantum Computing Attacks

**Threat:** Shor's algorithm breaks ECDSA.

**Rationale:**
- Not currently practical
- Post-quantum migration is industry-wide effort
- Ephemeral keys limit retroactive compromise risk
- Will adopt post-quantum algorithms when standardized

---

## Security Guarantees

### What Keyless Signing Provides

✅ **Authenticity** - Signature proves WASM module came from specific OIDC identity
✅ **Integrity** - Any modification to module invalidates signature
✅ **Non-Repudiation** - Public Rekor log prevents denial of signing
✅ **Freshness** - Rekor timestamp proves when signature was created
✅ **Auditability** - All signatures publicly logged and verifiable
✅ **No Key Management** - No long-lived private keys to protect

### What Keyless Signing Does NOT Provide

❌ **Revocation** - Cannot revoke a signature after creation (certificate expired anyway)
❌ **Offline Verification** - Requires Rekor access for inclusion proof
❌ **Anonymity** - OIDC identity is in certificate (intentional)
❌ **Forward Secrecy** - Compromise of Fulcio CA root invalidates all past signatures

### Security Comparison: Keyless vs Certificate-Based

| Property | Keyless | Certificate-Based |
|----------|---------|-------------------|
| **Offline verification** | ❌ No (needs Rekor) | ✅ Yes |
| **Key management** | ✅ None | ❌ Complex |
| **Transparency log** | ✅ Yes (Rekor) | ❌ No |
| **Hardware security** | ⚠️ Optional | ✅ Yes (ATECC608) |
| **Revocation** | ❌ Expiry only | ❌ Expiry only |
| **Internet required** | ✅ Yes (signing) | ❌ No |
| **Best for** | CI/CD, cloud | IoT, embedded, air-gapped |

---

## Operational Security

### For Users (Developers)

#### Using Keyless Signing in CI/CD

**GitHub Actions Example:**
```yaml
permissions:
  id-token: write  # Required for OIDC token

steps:
  - uses: actions/checkout@v4
  - run: wasmsign2 sign --keyless -i module.wasm -o signed.wasm
```

**Security Checklist:**
- ✅ Enable `id-token: write` permission
- ✅ Verify workflow identity matches expectations
- ✅ Review Rekor log for unexpected signatures
- ✅ Use branch protection to control who can trigger workflows

#### Verifying Keyless Signatures

**Verification includes:**
1. Certificate chain validation (to Fulcio root CA)
2. Certificate validity at Rekor timestamp
3. Signature verification against module hash
4. Rekor inclusion proof verification
5. Optional: identity and issuer validation

**Example:**
```rust
KeylessVerifier::verify(
    &module,
    Some("https://github.com/owner/repo/.github/workflows/build.yml@refs/heads/main"),
    Some("https://token.actions.githubusercontent.com")
)?;
```

#### Monitoring and Auditing

**Monitor Rekor for:**
- Unexpected signatures from your identity
- Signatures outside normal build times
- Signatures for unknown modules

**Tools:**
- Rekor search API: `https://rekor.sigstore.dev/api/v1/log/entries/retrieve`
- Monitor by identity: Check for your OIDC subject claim

### For Operators (Infrastructure)

#### Secure Environment Variables

**OIDC tokens are sensitive:**
- Never log `ACTIONS_ID_TOKEN_REQUEST_TOKEN`
- Tokens are single-use but should be zeroized
- Use GitHub's OIDC provider security best practices

#### Network Security

**Outbound HTTPS Required:**
- `https://fulcio.sigstore.dev` - Certificate issuance
- `https://rekor.sigstore.dev` - Transparency log
- `https://token.actions.githubusercontent.com` - OIDC (GitHub)

**Firewall Rules:**
- Allow outbound HTTPS (port 443)
- Certificate pinning available (future - Issue #12)

#### Rate Limiting

**Note:** Currently no rate limiting (Issue #6)
- Fulcio/Rekor have their own rate limits
- Excessive signing may be throttled by Sigstore

---

## Certificate-Based Signing Security

(See `docs/security-analysis.md` for comprehensive coverage)

**Summary:**
- Uses Ed25519 signatures with SHA-256
- Supports multi-signature workflows
- Hardware-backed keys (ATECC608)
- Offline verification capability
- Certificate expiry provides revocation

---

## Comparison with Other Systems

### vs. Sigstore Cosign

wsc's keyless signing **is built on** Sigstore infrastructure (Fulcio + Rekor) but targets WASM modules specifically.

| Feature | wsc | Cosign |
|---------|-----|--------|
| WASM Support | ✅ Native | ⚠️ Via blob |
| Keyless | ✅ Yes | ✅ Yes |
| Fulcio | ✅ Yes | ✅ Yes |
| Rekor | ✅ Yes | ✅ Yes |
| Multi-signature | ✅ Composition | ✅ Attestations |
| Hardware keys | ✅ ATECC608 | ❌ Software only (keyless) |
| Offline | ✅ Cert mode | ✅ Key mode |

### vs. Traditional Code Signing

| Feature | wsc Keyless | Apple Code Sign | Windows Authenticode |
|---------|-------------|-----------------|---------------------|
| Algorithm | ECDSA P-256 | RSA/ECDSA | RSA |
| Timestamp | Rekor | TSA | TSA |
| Hardware | Optional | Optional (T2) | Optional (HSM) |
| Transparency | ✅ Rekor | ❌ No | ❌ No |
| Revocation | ❌ Expiry | ✅ CRL/OCSP | ✅ CRL/OCSP |
| Key Mgmt | ✅ None | ❌ Complex | ❌ Complex |
| Cost | Free | $99+/year | $100+/year |

---

## Reporting Security Issues

**Do not open public issues for security vulnerabilities.**

Contact: [security contact from repository settings]

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested mitigation (if any)

---

## Security Changelog

### v0.2.7
- ✅ Added ephemeral key zeroization (Issue #14)
- ✅ Added OIDC token zeroization (Issue #11)
- ✅ Implemented Rekor inclusion proof verification (Issue #15)
- ✅ Sanitized error messages for information disclosure (Issue #9)
- ✅ Added comprehensive zeroization tests (17 new tests)

### Previous
- ✅ Implemented Rekor checkpoint-based verification (Issue #1)
- ✅ Full certificate chain verification (Issue #16)

---

## References

- [Sigstore Documentation](https://docs.sigstore.dev/)
- [Fulcio CA](https://docs.sigstore.dev/fulcio/overview)
- [Rekor Transparency Log](https://docs.sigstore.dev/rekor/overview)
- [ECDSA P-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
- [RFC 6962: Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
- [RFC 6979: Deterministic ECDSA](https://datatracker.ietf.org/doc/html/rfc6979)

---

**Last Updated:** 2025-01-15
**Addresses:** Issues #2 (Security Model Documentation), #4 (Ephemeral Key Lifecycle)
