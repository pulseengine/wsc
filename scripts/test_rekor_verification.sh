#!/bin/bash
set -e

# Test Rekor verification with fresh data
# This script creates a fresh keyless signature using cosign and validates
# our Rekor verification implementation against it

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/../target/rekor_test"
mkdir -p "$TEST_DIR"

echo "🔐 Testing Rekor Verification with Fresh Data"
echo "=============================================="
echo ""

# Step 1: Create test artifact
echo "📝 Step 1: Creating test artifact..."
TEST_FILE="$TEST_DIR/test_artifact.txt"
echo "Hello from wasmsign2 Rekor test $(date)" > "$TEST_FILE"
echo "   ✅ Created: $TEST_FILE"
echo ""

# Step 2: Sign with keyless (requires OIDC login)
echo "🔑 Step 2: Signing with cosign keyless (OIDC required)..."
echo "   ⚠️  This will open a browser for OIDC authentication"
echo ""

BUNDLE_FILE="$TEST_DIR/test_artifact.txt.bundle"

# Use --bundle to get the new bundle format with all verification data
if cosign sign-blob "$TEST_FILE" \
    --bundle="$BUNDLE_FILE" \
    --yes \
    > "$TEST_DIR/signature.txt" 2>&1; then
    echo "   ✅ Signed successfully!"
else
    echo "   ❌ Signing failed. Output:"
    cat "$TEST_DIR/signature.txt"
    exit 1
fi
echo ""

# Step 3: Extract bundle data
echo "📦 Step 3: Extracting bundle data..."

if [ ! -f "$BUNDLE_FILE" ]; then
    echo "   ❌ Bundle file not found: $BUNDLE_FILE"
    exit 1
fi

# Pretty print the bundle
echo "   Bundle contents:"
jq '.' "$BUNDLE_FILE" > "$TEST_DIR/bundle_pretty.json"
cat "$TEST_DIR/bundle_pretty.json"
echo ""

# Extract logIndex
LOG_INDEX=$(jq -r '.rekorBundle.Payload.logIndex' "$BUNDLE_FILE")
if [ -z "$LOG_INDEX" ] || [ "$LOG_INDEX" = "null" ]; then
    echo "   ❌ Could not extract logIndex from bundle"
    exit 1
fi
echo "   ✅ Rekor logIndex: $LOG_INDEX"

# Extract other useful data
INTEGRATED_TIME=$(jq -r '.rekorBundle.Payload.integratedTime' "$BUNDLE_FILE")
LOG_ID=$(jq -r '.rekorBundle.Payload.logID' "$BUNDLE_FILE")
echo "   ✅ Integrated time: $INTEGRATED_TIME"
echo "   ✅ Log ID: $LOG_ID"
echo ""

# Step 4: Fetch full Rekor entry
echo "🌐 Step 4: Fetching Rekor entry from transparency log..."
REKOR_URL="https://rekor.sigstore.dev/api/v1/log/entries?logIndex=$LOG_INDEX"
echo "   URL: $REKOR_URL"

REKOR_ENTRY_FILE="$TEST_DIR/rekor_entry.json"
if curl -s "$REKOR_URL" > "$REKOR_ENTRY_FILE"; then
    echo "   ✅ Fetched Rekor entry"

    # Pretty print
    jq '.' "$REKOR_ENTRY_FILE" > "$TEST_DIR/rekor_entry_pretty.json"

    # Extract key fields
    UUID=$(jq -r 'keys[0]' "$REKOR_ENTRY_FILE")
    echo "   ✅ Entry UUID: $UUID"

    # Extract verification data
    BODY=$(jq -r ".\"$UUID\".body" "$REKOR_ENTRY_FILE")
    SET=$(jq -r ".\"$UUID\".verification.signedEntryTimestamp" "$REKOR_ENTRY_FILE")
    INCLUSION_PROOF=$(jq -c ".\"$UUID\".verification.inclusionProof" "$REKOR_ENTRY_FILE")

    echo "   ✅ Extracted body, SET, and inclusion proof"
else
    echo "   ❌ Failed to fetch Rekor entry"
    exit 1
fi
echo ""

# Step 5: Generate Rust test data
echo "🦀 Step 5: Generating Rust test data..."
TEST_DATA_FILE="$SCRIPT_DIR/../src/lib/src/signature/keyless/rekor_verifier.rs.test_data/fresh_entry_$(date +%Y%m%d_%H%M%S).json"
mkdir -p "$(dirname "$TEST_DATA_FILE")"

cat > "$TEST_DATA_FILE" <<EOF
{
  "description": "Fresh Rekor entry created on $(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "uuid": "$UUID",
  "logIndex": $LOG_INDEX,
  "body": "$BODY",
  "logID": "$LOG_ID",
  "signedEntryTimestamp": "$SET",
  "inclusionProof": $INCLUSION_PROOF,
  "integratedTime": "$INTEGRATED_TIME",
  "rekor_url": "$REKOR_URL"
}
EOF

echo "   ✅ Saved test data to: $TEST_DATA_FILE"
echo ""

# Step 6: Display summary
echo "✅ SUCCESS! Fresh Rekor entry created and validated"
echo "=================================================="
echo ""
echo "📊 Test Data Summary:"
echo "   Log Index:        $LOG_INDEX"
echo "   UUID:             $UUID"
echo "   Integrated Time:  $INTEGRATED_TIME"
echo "   Log ID:           $LOG_ID"
echo ""
echo "📁 Generated Files:"
echo "   Test artifact:    $TEST_FILE"
echo "   Bundle:           $BUNDLE_FILE"
echo "   Rekor entry:      $REKOR_ENTRY_FILE"
echo "   Rust test data:   $TEST_DATA_FILE"
echo ""
echo "🔍 Next Steps:"
echo "   1. Use the data in $TEST_DATA_FILE to create a Rust test"
echo "   2. Verify SET signature with our implementation"
echo "   3. Verify inclusion proof with our implementation"
echo ""
echo "💡 To verify with cosign:"
echo "   cosign verify-blob $TEST_FILE --bundle $BUNDLE_FILE --certificate-identity=<your-email> --certificate-oidc-issuer=https://oauth2.sigstore.dev/auth"
