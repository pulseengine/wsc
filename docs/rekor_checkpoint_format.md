# Rekor Checkpoint Format Specification

## Executive Summary

Checkpoints (also called Signed Tree Heads or STH) are cryptographically signed commitments to a Merkle tree state. They solve the "tree growth problem" where the root hash changes as new entries are added. By verifying checkpoints instead of directly comparing root hashes, we can handle inclusion proofs even when the tree has grown since the proof was generated.

## Format Specification

A checkpoint consists of two parts separated by a blank line:
1. **Checkpoint Note** (unsigned data)
2. **Checkpoint Signature** (signed commitment to the note)

### Complete Format

```
<origin>
<tree_size>
<root_hash_base64>
[optional: <other_content>]...

— <name> <key_fingerprint_and_signature_base64>
```

### Real Production Example

From rekor.sigstore.dev (log index 539031017):

```
rekor.sigstore.dev - 1193050959916656506
539255994
pVjW9KXwFpmLLTGeIiRWgSMwacaZ0oA2HndJrNMYd18=

— rekor.sigstore.dev wNI9ajBFAiB7nJlPT8/1/K2hdXgYofIHhKfHfNBjcXHzyK2VnaSfxQIhAIkP5J3E8pGdfAII7w1H4SCekse5e7GRsFK190G7FaEe
```

**Breakdown:**
- **Origin**: `rekor.sigstore.dev - 1193050959916656506`
  - Hostname: `rekor.sigstore.dev`
  - Tree ID: `1193050959916656506` (decimal representation of shard ID)
- **Tree Size**: `539255994` (number of entries in the tree at this checkpoint)
- **Root Hash**: `pVjW9KXwFpmLLTGeIiRWgSMwacaZ0oA2HndJrNMYd18=` (base64-encoded 32-byte hash)
- **Signature**: `— rekor.sigstore.dev wNI9a...`
  - Name: `rekor.sigstore.dev`
  - Combined data: `wNI9a...` (key fingerprint + signature)

## Component Details

### 1. Checkpoint Note Structure

The note is the data that gets signed. Format (each line ends with `\n`):

```
<origin>\n
<tree_size>\n
<root_hash_base64>\n
[<other_content>\n]...
```

**Fields:**
- `origin` (String): Unique identifier combining hostname and tree ID
  - Format: `<hostname> - <tree_id>`
  - Example: `rekor.sigstore.dev - 1193050959916656506`
  - Purpose: Identifies which log/shard this checkpoint is for

- `tree_size` (u64): Number of entries in the Merkle tree
  - Decimal string representation
  - Example: `539255994`
  - Used for consistency proof verification

- `root_hash` (32 bytes): Merkle tree root hash
  - Base64 Standard encoding
  - Example: `pVjW9KXwFpmLLTGeIiRWgSMwacaZ0oA2HndJrNMYd18=`
  - Decodes to 32-byte SHA-256 hash

- `other_content` (Optional): Additional metadata
  - Format: Key-value pairs like `Timestamp: 1689748607742585419`
  - Or plain text lines
  - Each line separated by `\n`

### 2. Checkpoint Signature Structure

The signature follows the note after a blank line (`\n\n`):

```
— <name> <fingerprint_and_signature_base64>\n
```

**Fields:**
- `—` (em dash, U+2014): Signature marker
- `name` (String): Identity of the signer
  - Usually the hostname or a key identifier
  - Example: `rekor.sigstore.dev`
- `fingerprint_and_signature` (Base64): Combined data
  - First 4 bytes: Key fingerprint (first 4 bytes of SHA-256(PKIX public key))
  - Remaining bytes: Raw signature over the note
  - Example breakdown:
    ```
    wNI9ajBF... (base64)
    ↓ decode
    [0xc0, 0xd2, 0x3d, 0x6a] + [signature bytes...]
    ↑                          ↑
    key fingerprint (4 bytes)  ECDSA signature
    ```

### 3. Signature Computation

The signature is computed over the **marshaled checkpoint note** (not the full checkpoint):

**Input to signature:**
```
rekor.sigstore.dev - 1193050959916656506\n
539255994\n
pVjW9KXwFpmLLTGeIiRWgSMwacaZ0oA2HndJrNMYd18=\n
```

**Signature algorithm** (based on key type):
- **ECDSA** (most common for Rekor):
  - Hash: SHA-256 of note
  - Signature: ECDSA P-256 signature over the hash
- **Ed25519**: Direct signature over note (no pre-hashing)
- **RSA**: PSS signature with SHA-256

**Verification pseudocode:**
```rust
let note_bytes = checkpoint.note.marshal().as_bytes();
let digest = SHA256(note_bytes);
rekor_key.verify_signature(signature_bytes, digest)
```

## Implementation References

### Rekor (Go)

**Creation** (`/tmp/rekor/pkg/util/checkpoint.go:147-165`):
```go
func CreateAndSignCheckpoint(ctx context.Context, hostname string, treeID int64,
    treeSize uint64, rootHash []byte, signer signature.Signer) ([]byte, error) {

    sth, err := CreateSignedCheckpoint(Checkpoint{
        Origin: fmt.Sprintf("%s - %d", hostname, treeID),
        Size:   treeSize,
        Hash:   rootHash,
    })

    if _, err := sth.Sign(hostname, signer, options.WithContext(ctx)); err != nil {
        return nil, err
    }

    return sth.MarshalText()
}
```

**Marshaling** (`/tmp/rekor/pkg/util/checkpoint.go:45-52`):
```go
func (c Checkpoint) String() string {
    var b strings.Builder
    fmt.Fprintf(&b, "%s\n%d\n%s\n", c.Origin, c.Size,
        base64.StdEncoding.EncodeToString(c.Hash))
    for _, line := range c.OtherContent {
        fmt.Fprintf(&b, "%s\n", line)
    }
    return b.String()
}
```

**Verification** (`/tmp/rekor/pkg/util/signed_note.go:74-115`):
```go
func (s SignedNote) Verify(verifier signature.Verifier) bool {
    msg := []byte(s.Note)
    digest := sha256.Sum256(msg)

    pk, _ := verifier.PublicKey()
    verifierPkHash, _ := getPublicKeyHash(pk)

    for _, s := range s.Signatures {
        sigBytes, _ := base64.StdEncoding.DecodeString(s.Base64)

        if s.Hash != verifierPkHash {
            return false  // Key fingerprint mismatch
        }

        opts := []signature.VerifyOption{}
        switch pk.(type) {
        case *ecdsa.PublicKey:
            opts = append(opts, options.WithDigest(digest[:]))
        case ed25519.PublicKey:
            // No digest option for Ed25519
        }

        return verifier.VerifySignature(sigBytes, msg, opts...) == nil
    }
}
```

### sigstore-rs (Rust)

**Parsing** (`/tmp/sigstore-rs/src/rekor/models/checkpoint.rs:71-84`):
```rust
fn decode(s: &str) -> Result<Self, ParseCheckpointError> {
    let checkpoint = s.trim_start_matches('"').trim_end_matches('"');

    let Some((note, signature)) = checkpoint.split_once("\n\n") else {
        return Err(DecodeError("unexpected checkpoint format".to_string()));
    };

    let signature = CheckpointSignature::decode(signature)?;
    let note = CheckpointNote::unmarshal(note)?;

    Ok(Checkpoint { note, signature })
}
```

**Signature verification** (`/tmp/sigstore-rs/src/rekor/models/checkpoint.rs:94-99`):
```rust
pub fn verify_signature(&self, rekor_key: &CosignVerificationKey) -> Result<(), SigstoreError> {
    rekor_key.verify_signature(
        Signature::Raw(&self.signature.raw),
        self.note.marshal().as_bytes(),
    )
}
```

**Checkpoint validation with proof** (`/tmp/sigstore-rs/src/rekor/models/checkpoint.rs:102-116`):
```rust
pub(crate) fn is_valid_for_proof(
    &self,
    proof_root_hash: &Output<Rfc6269Default>,
    proof_tree_size: u64,
) -> Result<(), SigstoreError> {
    // Uses consistency proof logic:
    // If checkpoint.size == proof.tree_size, just compare hashes
    // If checkpoint.size < proof.tree_size, verify consistency proof
    Rfc6269Default::verify_consistency(
        self.note.size,
        proof_tree_size,
        &[],  // Empty proof means size equality check
        &self.note.hash.into(),
        proof_root_hash,
    )
    .map_err(ConsistencyProofError)
}
```

## Key Fingerprint Computation

The 4-byte key fingerprint is used to quickly identify which key should verify the signature:

```go
func getPublicKeyHash(publicKey crypto.PublicKey) (uint32, error) {
    pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {
        return 0, err
    }
    pkSha := sha256.Sum256(pubKeyBytes)
    hash := binary.BigEndian.Uint32(pkSha[:])  // First 4 bytes
    return hash, nil
}
```

**Example:**
```
Public Key (PKIX DER encoding) → SHA-256 → [0xc0, 0xd2, 0x3d, 0x6a, ...]
                                              ↑________________↑
                                              Fingerprint = 0xc0d23d6a
```

## Checkpoint-Based Verification Flow

Instead of directly comparing root hashes, use checkpoint verification:

```rust
// 1. Parse checkpoint from inclusion proof
let checkpoint = Checkpoint::decode(&proof.checkpoint)?;

// 2. Verify checkpoint signature (proves log signed this tree state)
checkpoint.verify_signature(rekor_key)?;

// 3. Validate checkpoint matches proof (handles tree growth)
checkpoint.is_valid_for_proof(&proof.root_hash, proof.tree_size)?;

// 4. Compute leaf hash from entry body
let leaf_hash = merkle::compute_leaf_hash(&body_bytes);

// 5. Verify inclusion using proof data (NOT checkpoint data)
merkle::verify_inclusion_proof(
    proof.log_index,    // Physical index in shard
    proof.tree_size,    // Shard's tree size (may differ from checkpoint)
    &leaf_hash,
    &proof_hashes,
    &proof.root_hash,   // Use proof's root, not checkpoint's
)?;
```

## Why Checkpoints Solve the Tree Growth Problem

**Problem without checkpoints:**
```
Time T1: Entry added at index 539031017
  ├─ Tree size: 539031018
  ├─ Root hash: AAAA...
  └─ Inclusion proof generated

Time T2: Verification happens (100+ new entries added)
  ├─ Current tree size: 539031120
  ├─ Root hash: BBBB... (different!)
  └─ Inclusion proof fails! ❌
```

**Solution with checkpoints:**
```
Time T1: Entry added at index 539031017
  ├─ Inclusion proof references checkpoint at size 539031018
  └─ Checkpoint signed: "I commit that tree size 539031018 has root AAAA"

Time T2: Verification happens (tree has grown)
  ├─ Current tree size: 539031120 (ignored)
  ├─ Checkpoint signature verifies ✅
  ├─ Checkpoint size (539031018) matches proof size ✅
  └─ Inclusion proof verifies against checkpoint's root ✅
```

The checkpoint acts as a **notarized snapshot** - the log's signature proves "at this point in time, the tree had this size and root hash."

## Test Vectors

### Minimal Valid Checkpoint

```
Log Checkpoint v0
123
YmFuYW5hcw==

— someone pOhM+S/mYjEYtQsOF4lL8o/dR+nbjoz5Cvg/n486KIismpVq0s4wxBaakmryI7zThjWAqRUyECPL3WSEcVDEBQ==
```

### With Additional Content

```
Banana Checkpoint v7
9943
AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
Timestamp: 1689748607742585419

— someone pOhM+S/mYjEYtQsOF4lL8o/dR+nbjoz5Cvg/n486KIismpVq0s4wxBaakmryI7zThjWAqRUyECPL3WSEcVDEBQ==
```

## Implementation Status

| Component | wasmsign2 | Status |
|-----------|-----------|---------|
| Checkpoint parsing | ❌ Not implemented | Need to add |
| Checkpoint signature verification | ❌ Not implemented | Can reuse SET verification code |
| Checkpoint-based inclusion proof | ❌ Not implemented | Critical for fixing root hash mismatch |
| Direct root hash comparison | ✅ Implemented | Works but brittle (tree growth issue) |

## Next Steps for wasmsign2

1. **Add checkpoint parsing**
   - Create `Checkpoint` struct with `Note` and `Signature` fields
   - Implement `decode()` to parse checkpoint string format
   - Parse origin, size, hash from note section

2. **Implement checkpoint signature verification**
   - Extract key fingerprint from signature
   - Verify fingerprint matches Rekor public key
   - Verify ECDSA signature over marshaled note
   - Can reuse existing `verify_ecdsa_signature()` code

3. **Add `is_valid_for_proof()` validation**
   - Compare checkpoint.size with proof.tree_size
   - If equal: verify checkpoint.hash == proof.root_hash
   - If checkpoint is older: verify consistency proof (may be empty)

4. **Update inclusion proof verification**
   - Use checkpoint root hash as reference instead of direct comparison
   - This allows verification even when tree has grown

## References

- **Checkpoint Format**: Based on [transparency-dev/formats](https://github.com/transparency-dev/formats/blob/main/log/checkpoint.go)
- **Rekor Implementation**: `/tmp/rekor/pkg/util/checkpoint.go`
- **sigstore-rs Implementation**: `/tmp/sigstore-rs/src/rekor/models/checkpoint.rs`
- **Signed Note Format**: [golang.org/x/mod/sumdb/note](https://pkg.go.dev/golang.org/x/mod/sumdb/note)
- **RFC 6962 (Certificate Transparency)**: https://www.rfc-editor.org/rfc/rfc6962.html
