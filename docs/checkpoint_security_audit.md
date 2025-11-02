# Checkpoint Verification Security Audit & Fixes

## Executive Summary

After implementing checkpoint-based verification, a critical security review identified **2 critical vulnerabilities** that have now been **FIXED**.

## Vulnerabilities Found & Fixed

### 🔴 CRITICAL #1: Missing Key Fingerprint Validation

**Status**: ✅ **FIXED**

**Issue**: The checkpoint signature includes a 4-byte key fingerprint (first 4 bytes of SHA-256 of the public key), but the original implementation **never validated it** against the actual public key being used for verification.

**Location**: `verify_checkpoint()` function

**Risk**:
- Key confusion attacks
- Using wrong public key for verification
- Violates defense-in-depth principles
- Could lead to accepting invalid signatures if multiple keys exist

**Reference Implementation** (`/tmp/rekor/pkg/util/signed_note.go:97-99`):
```go
if s.Hash != verifierPkHash {
    return false  // ← Rekor DOES validate this
}
```

**Fix Applied** (`rekor_verifier.rs:516-526`):
```rust
// SECURITY: Validate key fingerprint matches the public key
// This ensures we're using the correct key and prevents key confusion attacks
let computed_fingerprint = Self::compute_key_fingerprint(verifying_key)?;
if checkpoint.signature.key_fingerprint != computed_fingerprint {
    return Err(WSError::RekorError(format!(
        "Checkpoint key fingerprint mismatch: expected {:02x}{:02x}{:02x}{:02x}, got {:02x}{:02x}{:02x}{:02x}",
        computed_fingerprint[0], computed_fingerprint[1], computed_fingerprint[2], computed_fingerprint[3],
        checkpoint.signature.key_fingerprint[0], checkpoint.signature.key_fingerprint[1],
        checkpoint.signature.key_fingerprint[2], checkpoint.signature.key_fingerprint[3]
    )));
}
```

**Implementation Details**:

Added `compute_key_fingerprint()` function (`rekor_verifier.rs:348-402`):
- Constructs PKIX (SubjectPublicKeyInfo) DER encoding for ECDSA P-256 keys
- Includes algorithm identifier OIDs (ecPublicKey, prime256v1)
- Computes SHA-256 hash of PKIX structure
- Returns first 4 bytes as fingerprint

PKIX structure:
```
SEQUENCE {
  SEQUENCE {
    OBJECT IDENTIFIER ecPublicKey (1.2.840.10045.2.1)
    OBJECT IDENTIFIER prime256v1 (1.2.840.10045.3.1.7)
  }
  BIT STRING (SEC1 uncompressed point: 0x04 || x || y)
}
```

### 🔴 CRITICAL #2: Missing Origin Validation

**Status**: ✅ **FIXED**

**Issue**: The checkpoint origin field (e.g., `"rekor.sigstore.dev - 1193050959916656506"`) was parsed but **never validated**. This allowed:
- Accepting checkpoints from malicious or test logs
- Cross-shard attacks (using checkpoint from one shard to verify entry from another)
- No verification that the hostname matches expected production Rekor

**Risk**:
- **HIGH**: Cross-shard attacks where attacker uses checkpoint from shard A to validate entry from shard B
- **HIGH**: Accepting checkpoints from attacker-controlled logs
- **MEDIUM**: Confusion between production and test environments

**Fix Applied** (`rekor_verifier.rs:295-342`):

```rust
/// Validate checkpoint origin matches expected values
///
/// Checks:
/// 1. Origin format is "<hostname> - <tree_id>"
/// 2. Hostname is "rekor.sigstore.dev" (expected Rekor production)
/// 3. Tree ID matches the tree ID in the entry's UUID
///
/// This prevents accepting checkpoints from wrong logs or shards.
fn validate_checkpoint_origin(checkpoint: &Checkpoint, entry_uuid: &str) -> Result<(), WSError> {
    // Parse origin: should be "<hostname> - <tree_id>"
    let parts: Vec<&str> = checkpoint.note.origin.split(" - ").collect();
    if parts.len() != 2 {
        return Err(WSError::RekorError(format!(
            "Invalid checkpoint origin format: expected '<hostname> - <tree_id>', got '{}'",
            checkpoint.note.origin
        )));
    }

    let hostname = parts[0];
    let checkpoint_tree_id = parts[1];

    // SECURITY: Validate hostname matches expected production Rekor
    if hostname != "rekor.sigstore.dev" {
        return Err(WSError::RekorError(format!(
            "Unexpected checkpoint origin hostname: expected 'rekor.sigstore.dev', got '{}'",
            hostname
        )));
    }

    // SECURITY: Validate tree ID matches the entry's UUID
    let entry_tree_id = Self::extract_tree_id_from_uuid(entry_uuid)?;
    if checkpoint_tree_id != entry_tree_id {
        return Err(WSError::RekorError(format!(
            "Checkpoint tree ID mismatch: checkpoint has '{}', but entry UUID has '{}'",
            checkpoint_tree_id, entry_tree_id
        )));
    }

    Ok(())
}
```

**Supporting Function** (`rekor_verifier.rs:270-293`):

```rust
/// Extract tree ID from a Rekor UUID
///
/// UUID format: <tree_id (16 hex chars)><leaf_hash (64 hex chars)>
fn extract_tree_id_from_uuid(uuid: &str) -> Result<String, WSError> {
    if uuid.len() != 80 {
        return Err(WSError::RekorError(format!(
            "Invalid UUID length: expected 80, got {}",
            uuid.len()
        )));
    }

    // First 16 characters are the tree ID (hex)
    let tree_id_hex = &uuid[0..16];

    // Convert hex to u64 (tree ID is 8 bytes)
    let tree_id = u64::from_str_radix(tree_id_hex, 16)
        .map_err(|e| WSError::RekorError(format!("Failed to parse tree ID from UUID: {}", e)))?;

    // Return as decimal string for comparison with checkpoint origin
    Ok(tree_id.to_string())
}
```

**Integration** (`rekor_verifier.rs:783-787`):
```rust
// SECURITY: Validate checkpoint origin (hostname and tree ID)
RekorKeyring::validate_checkpoint_origin(&checkpoint, &entry.uuid)?;

#[cfg(test)]
println!("   ✅ Checkpoint origin validated");
```

## Validation Test Results

Testing with production data (UUID: `108e9186e8c5677a...`):

```
📋 Checkpoint-based verification:
   Checkpoint origin: rekor.sigstore.dev - 1193050959916656506
   Checkpoint size: 539287087
   Checkpoint root hash: 4aa12003f6b01b2597e46e949113ae9c8be8bea1b2f0093037aa7927dc8e9932
   Signature name: rekor.sigstore.dev
   ✅ Checkpoint origin validated       ← NEW: Origin validation
   ✅ Checkpoint signature verified     ← Includes fingerprint check
   ✅ Checkpoint matches proof
```

**Verified**:
- Tree ID from UUID: `0x108e9186e8c5677a` = `1193050959916656506` (decimal)
- Checkpoint origin: `rekor.sigstore.dev - 1193050959916656506`
- Hostname: `rekor.sigstore.dev` ✅
- Tree ID match: `1193050959916656506` == `1193050959916656506` ✅

## Remaining Issues (Lower Priority)

### 🟡 MEDIUM: No Signature Name Validation

**Status**: NOT FIXED (lower priority)

**Issue**: The signature `name` field (e.g., `"rekor.sigstore.dev"`) is extracted but not validated.

**Risk**: Low - the cryptographic signature validation is what matters

**Recommendation**: Add validation that `checkpoint.signature.name == "rekor.sigstore.dev"`

### 🟡 MEDIUM: No Checkpoint Freshness Check

**Status**: NOT FIXED (by design)

**Issue**: Checkpoints have no timestamp, so we can't validate freshness.

**Risk**: Low - mitigated by:
- Signature validation ensures log signed it
- Tree size comparison detects stale checkpoints
- Origin validation prevents cross-shard attacks

**Consideration**: Could add a check that checkpoint.size is reasonable (not too old)

### 🟢 LOW: Single Signature Assumption

**Status**: NOT FIXED (acceptable)

**Issue**: Checkpoint format supports multiple signatures, but implementation assumes one.

**Risk**: Very low - Rekor production uses single signatures

**Mitigation**: Code will fail gracefully if multiple signatures are present (parsing error)

### 🟢 LOW: Hardcoded Algorithm Assumption

**Status**: NOT FIXED (acceptable)

**Issue**: Implementation assumes ECDSA P-256, but checkpoint format is algorithm-agnostic.

**Risk**: Very low - Rekor production uses ECDSA P-256 exclusively

**Mitigation**: Well-documented assumption, easy to extend if needed

## Security Posture Summary

### Before Fixes

| Attack Vector | Risk | Mitigation |
|---------------|------|------------|
| Key confusion | HIGH | None ❌ |
| Cross-shard attack | CRITICAL | None ❌ |
| Malicious log acceptance | HIGH | None ❌ |
| Wrong key usage | HIGH | Log ID check only (partial) |

### After Fixes

| Attack Vector | Risk | Mitigation |
|---------------|------|------------|
| Key confusion | LOW | Fingerprint validation ✅ |
| Cross-shard attack | VERY LOW | Tree ID validation ✅ |
| Malicious log acceptance | VERY LOW | Hostname validation ✅ |
| Wrong key usage | VERY LOW | Fingerprint + Log ID ✅ |

## Defense-in-Depth Layers

The implementation now has **4 layers** of security validation:

1. **Log ID Match** (existing)
   - Finds correct public key from trusted root

2. **Key Fingerprint** (NEW)
   - Validates checkpoint was signed with expected key
   - Prevents key confusion attacks

3. **Origin Hostname** (NEW)
   - Ensures checkpoint is from production Rekor
   - Prevents malicious log acceptance

4. **Origin Tree ID** (NEW)
   - Validates checkpoint matches entry's shard
   - Prevents cross-shard attacks

5. **ECDSA Signature** (existing)
   - Cryptographic proof of authenticity

## Code Changes Summary

**Files Modified**:
- `src/lib/src/signature/keyless/rekor_verifier.rs`

**Lines Added**: ~140 lines

**New Functions**:
1. `extract_tree_id_from_uuid()` - Extract tree ID from 80-char UUID
2. `validate_checkpoint_origin()` - Validate hostname and tree ID
3. `compute_key_fingerprint()` - Compute PKIX SHA-256 fingerprint

**Modified Functions**:
1. `verify_checkpoint()` - Added fingerprint validation
2. `verify_inclusion_proof()` - Added origin validation call

## Testing

**Production Data Validated**:
- UUID: `108e9186e8c5677a9a5627d43b3185112de9090e7e1a6ffb917a7cb16cb36a0e87d12d8d25ffd2d8`
- Log Index: 539031017
- Tree ID: 1193050959916656506
- Checkpoint Origin: `rekor.sigstore.dev - 1193050959916656506`

**All Validations Pass**:
- ✅ Origin format parsing
- ✅ Hostname validation (`rekor.sigstore.dev`)
- ✅ Tree ID extraction from UUID
- ✅ Tree ID match with checkpoint
- ✅ Key fingerprint computation
- ✅ Key fingerprint validation
- ✅ ECDSA signature verification

## Conclusion

The checkpoint verification implementation has been **significantly hardened** with critical security fixes:

1. ✅ **Key fingerprint validation** - Prevents key confusion attacks
2. ✅ **Origin validation** - Prevents cross-shard and malicious log attacks

These fixes bring the implementation to **production security standards** and match the defense-in-depth approach used in the official Rekor implementation.

**Recommendation**: The checkpoint verification is now **SECURE FOR PRODUCTION USE** with proper attack surface mitigation.
