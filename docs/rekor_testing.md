# Local Rekor Verification Testing

## Overview

This document describes how to test Rekor verification locally using fresh, real data instead of stale test vectors.

## Why Local Testing is Better Than rekor-cli

**Advantages of our approach:**

1. **Fresh Data**: Creates NEW Rekor entries with current timestamps
2. **Full Control**: You own the test artifact and can reproduce the signing
3. **Complete Data**: Extracts ALL verification data (SET, inclusion proof, certificates)
4. **Automated**: Script generates Rust test data automatically
5. **Reproducible**: Can create multiple test cases with different OIDC providers

**Problems with rekor-cli:**
- Only fetches existing entries (can't create test data)
- Requires knowing logIndex or UUID beforehand
- Doesn't generate test code automatically
- Testing against old entries (like logIndex 0 from 2021) is unreliable

## Prerequisites

```bash
# Install cosign (macOS)
brew install cosign

# Or download from: https://github.com/sigstore/cosign/releases
```

## Testing Workflow

### Step 1: Create Fresh Rekor Entry

```bash
./scripts/test_rekor_verification.sh
```

This script will:
1. Create a test artifact
2. Sign it with keyless signing (opens browser for OIDC)
3. Upload signature to Rekor
4. Fetch the complete Rekor entry
5. Generate Rust test data

### Step 2: Authenticate with OIDC

When prompted, authenticate using one of:
- GitHub
- Google
- Microsoft

The browser will open automatically.

### Step 3: Review Generated Data

The script creates:
- `target/rekor_test/bundle_pretty.json` - Cosign bundle with all verification data
- `target/rekor_test/rekor_entry_pretty.json` - Full Rekor API response
- `src/lib/src/signature/keyless/rekor_verifier.rs.test_data/fresh_entry_*.json` - Rust test data

### Step 4: Create Rust Test

Use the generated JSON to create a test:

```rust
#[test]
fn test_verify_fresh_rekor_entry() {
    // Load the generated test data
    let test_data = include_str!("rekor_verifier.rs.test_data/fresh_entry_20250111_120000.json");
    let data: serde_json::Value = serde_json::from_str(test_data).unwrap();

    let entry = RekorEntry {
        uuid: data["uuid"].as_str().unwrap().to_string(),
        log_index: data["logIndex"].as_u64().unwrap(),
        body: data["body"].as_str().unwrap().to_string(),
        log_id: data["logID"].as_str().unwrap().to_string(),
        signed_entry_timestamp: data["signedEntryTimestamp"].as_str().unwrap().to_string(),
        inclusion_proof: serde_json::to_vec(&data["inclusionProof"]).unwrap(),
        integrated_time: /* convert from Unix timestamp */,
    };

    let keyring = RekorKeyring::from_embedded_trust_root().unwrap();

    // This should PASS with fresh data
    keyring.verify_entry(&entry).expect("Verification should succeed");
}
```

## Manual Verification

You can manually verify the signature with cosign:

```bash
cosign verify-blob target/rekor_test/test_artifact.txt \
    --bundle target/rekor_test/test_artifact.txt.bundle \
    --certificate-identity=<your-email> \
    --certificate-oidc-issuer=https://oauth2.sigstore.dev/auth
```

## Troubleshooting

### OIDC Authentication Fails

- Ensure you have a browser available
- Try a different OIDC provider (GitHub, Google, Microsoft)
- Check network connectivity

### Bundle Not Generated

- Ensure cosign version >= 3.0
- Check `cosign version`
- Update with `brew upgrade cosign`

### Rekor API Fetch Fails

- Check network connectivity
- Verify the logIndex in the bundle
- Try fetching manually: `curl https://rekor.sigstore.dev/api/v1/log/entries?logIndex=<INDEX>`

## Benefits of This Approach

1. **Always Current**: Tests against live Rekor infrastructure
2. **Realistic**: Uses actual OIDC flow and Fulcio certificates
3. **Debuggable**: Can inspect all intermediate data
4. **Flexible**: Easy to create multiple test cases
5. **CI-Ready**: Can be automated in CI with OIDC token

## Next Steps

Once verification works with fresh data:
1. Integrate into `cargo test`
2. Add CI test that creates fresh entries
3. Document expected vs actual behavior
4. Add regression tests with frozen test vectors
