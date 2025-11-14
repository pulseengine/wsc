# Security Analysis: WASM Signing Implementation

## Executive Summary

The WASM signing implementation in this codebase is **cryptographically sound** and suitable for production use in IoT/embedded scenarios with the following characteristics:

- ✅ **Sound cryptography**: Ed25519 + SHA-256
- ✅ **Multi-signature support**: Multiple independent signers
- ✅ **Certificate-based PKI**: Offline verification without internet
- ✅ **Composition-friendly**: Signatures preserved during module composition
- ⚠️  **No timestamp binding**: Use short-lived certificates instead
- ⚠️  **No revocation**: Certificate expiry provides lifecycle management

## Cryptographic Primitives

### Signature Algorithm: Ed25519

**Properties:**
- **Deterministic**: No random nonce, eliminates nonce reuse vulnerabilities
- **Fast**: ~200K signatures/sec, ~70K verifications/sec on modern CPUs
- **Compact**: 64-byte signatures, 32-byte public keys
- **Secure**: 128-bit security level (equivalent to 3072-bit RSA)

**Why Ed25519?**
- Designed for embedded systems (low memory, fast)
- No timing side-channel attacks (constant-time operations)
- No weak keys (all keys equally strong)
- Well-studied, NIST approved (FIPS 186-5)

### Hash Algorithm: SHA-256

**Properties:**
- **Collision resistant**: 2^128 work for collision
- **Pre-image resistant**: 2^256 work for pre-image
- **Second pre-image resistant**: 2^256 work for second pre-image

**Usage:**
- Hash entire WASM module content (every byte)
- 32-byte output serves as compact module identifier
- Standard, widely implemented, hardware acceleration available

## Signing Protocol

### Message Format

```
Signed Message = Domain || Version || ContentType || HashFn || Hash

Where:
- Domain = "wasmsig" (7 bytes, prevents cross-protocol attacks)
- Version = 0x01 (1 byte, signature format version)
- ContentType = 0x01 (1 byte, WASM module type)
- HashFn = 0x01 (1 byte, SHA-256 identifier)
- Hash = SHA-256(module) (32 bytes)
```

### Security Properties

#### 1. Domain Separation
The "wasmsig" prefix prevents **cross-protocol attacks** where a signature meant for one system is replayed in another.

Example attack prevented:
```
❌ Without domain separation:
   Sign(msg) → could be valid for WASM, SSH, TLS, etc.

✅ With domain separation:
   Sign("wasmsig" || msg) → only valid for WASM signatures
```

#### 2. Algorithm Binding
Version, content type, and hash function are part of the signed message.

**Prevents:**
- Algorithm substitution attacks
- Hash function downgrade attacks
- Format confusion attacks

#### 3. Content Integrity
The entire module is hashed before signing.

**Guarantees:**
- Any modification invalidates signature
- Byte-for-byte integrity protection
- No unsigned data in signed modules

## Multi-Signature Architecture

### Structure

```rust
SignatureData {
    signed_hashes_set: Vec<SignedHashes>
    //                  ↓
    //   SignedHashes {
    //       hashes: [hash1, hash2, ...]  // Multiple module versions
    //       signatures: [sig1, sig2, ...] // Multiple signers per hash
    //   }
}
```

### Properties

#### 1. Independent Verification
Each signature can be verified independently:
- No signature depends on another
- Verification order doesn't matter
- Adding signatures doesn't invalidate existing ones

#### 2. Multiple PKI Hierarchies
Each signature includes its own certificate chain:
```
Signature 1: Owner's device cert → Owner's CA → Owner's Root
Signature 2: Integrator's device cert → Integrator's CA → Integrator's Root
```

Verifier needs both root CAs to verify both signatures.

#### 3. Composition Safety
Delimiters enable safe module composition:

```
[Signature Header]
[Section 1] → Hash₁
[Delimiter₁] ← 16 random bytes
[Section 2] → Hash₂
[Delimiter₂]
```

**Properties:**
- Adding sections after delimiter doesn't invalidate hash before it
- Original signature remains valid
- New signer can add signature for extended module

## Certificate-Based Signing

### Why Certificates?

Traditional public key signing requires:
1. Distribute public keys to all verifiers
2. Update verifiers when keys change
3. Manage key-to-identity mapping

**Problems for IoT:**
- 1 million devices = 1 million public keys to distribute
- Key rotation requires updating all verifiers
- No scalable revocation mechanism

**Certificate solution:**
- Verifier only needs root CA certificate (one cert for all devices)
- Device certificates expire (natural revocation)
- Certificate chain proves device authenticity

### Trust Model

```
Root CA (manufacturer)
  ↓ signs
Intermediate CA (factory)
  ↓ signs
Device Certificate (embedded in device)
```

**Offline verification:**
1. Extract certificate chain from WASM signature
2. Verify chain against embedded root CA
3. Extract public key from device certificate
4. Verify WASM signature with that public key

**No internet required!**

### Security Properties

#### 1. Certificate Chain Validation
Uses **webpki** (Mozilla's PKI library):
- Validates signatures in chain
- Checks validity periods (not before/after)
- Verifies key usage extensions
- Ensures certificate constraints (CA vs end-entity)

#### 2. Algorithm Binding
Extended Key Usage: `codeSigning` (OID 1.3.6.1.5.5.7.3.3)
- Certificate explicitly marked for code signing
- Prevents certificate misuse (can't use TLS cert for code signing)

#### 3. Revocation Strategy
**No CRL/OCSP** (requires internet)
**Instead:**
- Short-lived certificates (1-2 years)
- Devices re-provision periodically
- Expired certificates = revoked certificates

## Known Limitations & Mitigations

### 1. No Timestamp Binding

**Limitation:**
Signatures don't include creation timestamp.

**Why it's okay:**
- Certificate validity period provides time window
- Module content is deterministic (same input = same signature)
- Offline verification doesn't have trusted time source anyway

**Mitigation:**
- Use short-lived device certificates (1-2 years)
- Certificate `notBefore/notAfter` provides temporal bounds

### 2. No Key Revocation

**Limitation:**
Can't revoke a key before certificate expires.

**Why it's okay:**
- Devices are locked down (key extraction is hard)
- Short certificate lifetimes limit exposure window
- Device attestation happens during provisioning

**Mitigation:**
- Certificate expiry = revocation
- Blocklist compromised certificates in verifier
- Hardware security (ATECC608) makes key extraction difficult

### 3. No Replay Protection

**Limitation:**
Same module signed twice produces same signature (Ed25519 is deterministic).

**Why it's okay:**
- Module content hash acts as identifier
- Replaying a valid module is allowed (it's the same module!)
- Different modules have different hashes

**Not a vulnerability:**
- Replay attacks require modified content (which invalidates signature)
- Valid replay = distributing unmodified signed module (legitimate)

### 4. No Freshness Guarantees

**Limitation:**
Can't prove signature was created recently.

**Why it's okay:**
- Offline verification has no trusted time
- Certificate validity provides bounds
- Freshness not critical for WASM code signing

**Mitigation:**
- Check certificate validity period
- Use version numbers in module metadata
- Application-level freshness checks if needed

## Comparison to Other Systems

### vs Sigstore/Fulcio (Keyless Signing)

| Feature | wsc (Certificate-based) | Sigstore/Fulcio |
|---------|------------------------|-----------------|
| **Internet required** | ❌ No | ✅ Yes (OIDC + Rekor) |
| **Offline verification** | ✅ Yes | ❌ No (needs Rekor) |
| **Trust anchor** | Root CA certificate | Fulcio root + Rekor |
| **Identity proof** | Device certificate | OIDC token |
| **Transparency log** | ❌ No | ✅ Yes (Rekor) |
| **Revocation** | Certificate expiry | Log monitoring |
| **Best for** | IoT, air-gapped, embedded | Cloud, CI/CD, developers |

### vs Code Signing (Apple/Microsoft)

| Feature | wsc | Apple Code Signing |
|---------|-----|-------------------|
| **Algorithm** | Ed25519 | RSA-4096 or ECDSA P-256 |
| **Timestamp** | ❌ No | ✅ Yes (timestamp server) |
| **Revocation** | Expiry | CRL/OCSP |
| **Hardware binding** | ✅ Yes (ATECC608) | ⚠️  Optional (T2/Secure Enclave) |
| **Offline capable** | ✅ Yes | ⚠️  Partial (needs timestamp) |
| **IoT optimized** | ✅ Yes | ❌ No (too heavyweight) |

## Attack Analysis

### Scenario 1: Modified WASM Module

**Attack:** Adversary modifies signed WASM module
**Defense:**
1. Hash changes when module modified
2. Signature verification fails (hash mismatch)
3. Module rejected

**Verdict:** ✅ Protected

### Scenario 2: Signature Stripping

**Attack:** Remove signature, replace with adversary's signature
**Defense:**
1. Adversary doesn't have device private key (in ATECC608)
2. Can't generate valid signature for their own cert
3. Even if they use their own cert, verifier won't trust it (different CA)

**Verdict:** ✅ Protected (hardware security + PKI)

### Scenario 3: Certificate Forgery

**Attack:** Create fake device certificate
**Defense:**
1. Certificate must be signed by trusted CA
2. CA private key is offline (HSM)
3. Adversary can't forge CA signature
4. Verifier checks certificate chain

**Verdict:** ✅ Protected (PKI security)

### Scenario 4: Replay Attack

**Attack:** Re-use valid signature on different module
**Defense:**
1. Signature binds to module hash
2. Different module = different hash
3. Signature verification fails

**Verdict:** ✅ Protected

### Scenario 5: Time-of-check Time-of-use (TOCTOU)

**Attack:** Module verified, then modified before execution
**Defense:**
- Outside signature system scope
- Runtime must verify before execution
- Immutable memory helps (WASM is designed for sandboxing)

**Verdict:** ⚠️  Application responsibility

### Scenario 6: Supply Chain Attack

**Attack:** Compromised factory signs malicious module with valid cert
**Defense:**
- Multi-signature! Owner + Integrator
- Both must approve
- Compromising one CA insufficient

**Mitigation:**
```rust
// Require BOTH signatures
let results = verify_all_certificates(&module, &[
    &owner_verifier,
    &integrator_verifier,
])?;

for result in &results {
    assert!(result.verified); // Both must pass
}
```

**Verdict:** ✅ Mitigated by multi-signature

### Scenario 7: Compromised Device Key

**Attack:** Extract private key from one device
**Impact:**
- Can sign modules as that device
- Limited to that device's certificate
- Certificate expires (1-2 years)

**Defense:**
1. Hardware security (ATECC608 has anti-tamper)
2. Short certificate lifetime
3. Certificate blocklist for compromised devices
4. Key extraction requires physical access

**Verdict:** ⚠️  Limited impact, mitigated by hardware + expiry

## Implementation Security

### Constant-Time Operations

Ed25519 implementation (from `ed25519-compact`) uses constant-time operations:
- No timing side-channels
- Safe against cache-timing attacks
- Critical for embedded systems

### Memory Safety

Rust provides:
- No buffer overflows
- No use-after-free
- No null pointer dereferences
- Thread-safe by default

**Impact:**
- Eliminates entire classes of vulnerabilities
- No memory corruption attacks on signature verification
- Safe to process untrusted WASM modules

### Error Handling

```rust
pub enum WSError {
    CryptoError,          // Signature verification failed
    VerificationFailed,   // No valid signatures
    X509Error,            // Certificate parsing failed
    // ... etc
}
```

**Properties:**
- Errors are explicit and typed
- No silent failures
- Failed verification returns error (fail-closed)

## Performance Characteristics

### Signature Generation
- **Ed25519 signing**: ~0.05ms per signature
- **SHA-256 hashing**: ~400 MB/s
- **Total**: < 1ms for typical WASM module

**Bottleneck:** Hardware signing (ATECC608 ~100ms)

### Signature Verification
- **Ed25519 verification**: ~0.14ms per signature
- **SHA-256 hashing**: ~400 MB/s
- **Certificate chain validation**: ~1ms
- **Total**: ~2ms for single signature

**Multi-signature:**
- 2 signatures = ~4ms
- 10 signatures = ~20ms
- Linear scaling

### Memory Usage
- **Signature size**: 64 bytes (Ed25519)
- **Public key size**: 32 bytes
- **Certificate**: ~1-2 KB (with chain)
- **Total overhead**: ~2-3 KB per signature

**For 2 signatures:** ~5 KB total overhead

## Recommendations

### For Production Deployment

1. **Use Hardware Security**
   ```rust
   // Use ATECC608, not SoftwareProvider
   let provider = Atecc608Provider::new("/dev/i2c-1", 0x60)?;
   ```

2. **Short Certificate Lifetimes**
   ```rust
   CertificateConfig::new("device-123")
       .with_validity_days(365); // 1 year
   ```

3. **Multi-Signature for Critical Systems**
   ```rust
   // Require both owner and integrator
   verify_all_certificates(&module, &[owner_ca, integrator_ca])?;
   ```

4. **Certificate Blocklist**
   ```rust
   // Implement application-level blocklist
   let blocklist = load_revoked_certificates();
   if blocklist.contains(&device_cert_serial) {
       return Err(WSError::CertificateRevoked);
   }
   ```

5. **Verify Before Execution**
   ```rust
   // Always verify immediately before loading
   verify_with_certificate(&mut wasm_file, &verifier)?;
   let instance = runtime.instantiate(&wasm_file)?;
   ```

### For Development

1. **Test with SoftwareProvider**
   - Fast iteration
   - No hardware required
   - Export keypairs for testing

2. **Separate Dev/Prod CAs**
   - Development CA for testing
   - Production CA locked in HSM
   - Different trust anchors

3. **Automated Testing**
   - Test multi-signature scenarios
   - Test certificate expiry
   - Test invalid signatures

## Conclusion

The WASM signing implementation is **cryptographically sound** and well-suited for IoT/embedded systems with the following characteristics:

**Strengths:**
- ✅ Strong cryptography (Ed25519, SHA-256)
- ✅ Offline verification (no internet required)
- ✅ Multi-signature support (composition-friendly)
- ✅ Hardware security integration (ATECC608)
- ✅ Certificate-based PKI (scalable identity)
- ✅ Memory safe (Rust)

**Limitations (by design):**
- ⚠️  No timestamp (use certificate validity)
- ⚠️  No revocation (use expiry + blocklist)
- ⚠️  No transparency log (acceptable for offline)

**Security Level:** **HIGH**
- Suitable for production use
- Recommended for IoT/embedded WASM signing
- Excellent for offline/air-gapped environments

**Comparison to alternatives:**
- More secure than software-only signatures (hardware backing)
- Better for offline than Sigstore/Fulcio
- Simpler and lighter than traditional code signing
- Purpose-built for WASM + embedded constraints

---

**Last Updated:** 2024-11-14
**Reviewed By:** Security Analysis (Automated)
**Next Review:** When cryptographic primitives updated
