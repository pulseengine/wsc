#!/bin/bash
set -e

# Fetch a recent Rekor entry for testing
# This doesn't require OIDC - just fetches existing data

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/../target/rekor_test"
mkdir -p "$TEST_DIR"

echo "🔍 Fetching Recent Rekor Entry for Testing"
echo "=========================================="
echo ""

# Step 1: Get current tree size
echo "📊 Step 1: Getting current Rekor tree size..."
LOG_INFO=$(curl -s "https://rekor.sigstore.dev/api/v1/log")
TREE_SIZE=$(echo "$LOG_INFO" | jq -r '.treeSize')
echo "   ✅ Current tree size: $TREE_SIZE"

# Get a recent entry (not the very latest, but recent)
RECENT_INDEX=$((TREE_SIZE - 1000))
echo "   Using logIndex: $RECENT_INDEX (recent but stable)"
echo ""

# Step 2: Fetch the entry
echo "🌐 Step 2: Fetching Rekor entry..."
REKOR_URL="https://rekor.sigstore.dev/api/v1/log/entries?logIndex=$RECENT_INDEX"
echo "   URL: $REKOR_URL"

REKOR_ENTRY_FILE="$TEST_DIR/recent_rekor_entry.json"
if curl -s "$REKOR_URL" > "$REKOR_ENTRY_FILE"; then
    echo "   ✅ Fetched Rekor entry"

    # Pretty print
    jq '.' "$REKOR_ENTRY_FILE" > "$TEST_DIR/recent_rekor_entry_pretty.json"

    # Extract UUID
    UUID=$(jq -r 'keys[0]' "$REKOR_ENTRY_FILE")
    echo "   ✅ Entry UUID: $UUID"

    # Extract all fields
    BODY=$(jq -r ".\"$UUID\".body" "$REKOR_ENTRY_FILE")
    LOG_ID=$(jq -r ".\"$UUID\".logID" "$REKOR_ENTRY_FILE")
    LOG_INDEX=$(jq -r ".\"$UUID\".logIndex" "$REKOR_ENTRY_FILE")
    INTEGRATED_TIME=$(jq -r ".\"$UUID\".integratedTime" "$REKOR_ENTRY_FILE")
    SET=$(jq -r ".\"$UUID\".verification.signedEntryTimestamp" "$REKOR_ENTRY_FILE")
    INCLUSION_PROOF=$(jq -c ".\"$UUID\".verification.inclusionProof" "$REKOR_ENTRY_FILE")

    echo "   ✅ Log Index: $LOG_INDEX"
    echo "   ✅ Integrated Time: $INTEGRATED_TIME"
    echo "   ✅ Log ID: $LOG_ID"
else
    echo "   ❌ Failed to fetch Rekor entry"
    exit 1
fi
echo ""

# Step 3: Convert integrated time to RFC3339
echo "🕒 Step 3: Converting timestamp..."
INTEGRATED_TIME_RFC3339=$(date -u -r "$INTEGRATED_TIME" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d "@$INTEGRATED_TIME" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null)
echo "   ✅ RFC3339: $INTEGRATED_TIME_RFC3339"
echo ""

# Step 4: Generate Rust test data
echo "🦀 Step 4: Generating Rust test data..."
TEST_DATA_FILE="$SCRIPT_DIR/../src/lib/src/signature/keyless/rekor_verifier.rs.test_data/recent_entry_$(date +%Y%m%d_%H%M%S).json"
mkdir -p "$(dirname "$TEST_DATA_FILE")"

cat > "$TEST_DATA_FILE" <<EOF
{
  "description": "Recent Rekor entry fetched on $(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "uuid": "$UUID",
  "logIndex": $LOG_INDEX,
  "body": "$BODY",
  "logID": "$LOG_ID",
  "signedEntryTimestamp": "$SET",
  "inclusionProof": $INCLUSION_PROOF,
  "integratedTime": "$INTEGRATED_TIME_RFC3339",
  "integratedTimeUnix": $INTEGRATED_TIME,
  "rekor_url": "$REKOR_URL"
}
EOF

echo "   ✅ Saved test data to: $TEST_DATA_FILE"
echo ""

# Step 5: Create Rust test code snippet
echo "🦀 Step 5: Generating Rust test code..."
cat > "$TEST_DIR/test_snippet.rs" <<'EOF'
#[test]
fn test_verify_recent_rekor_entry() {
    use super::super::RekorEntry;

    let test_data = include_str!("rekor_verifier.rs.test_data/recent_entry_*.json");
    let data: serde_json::Value = serde_json::from_str(test_data).unwrap();

    let entry = RekorEntry {
        uuid: data["uuid"].as_str().unwrap().to_string(),
        log_index: data["logIndex"].as_u64().unwrap(),
        body: data["body"].as_str().unwrap().to_string(),
        log_id: data["logID"].as_str().unwrap().to_string(),
        signed_entry_timestamp: data["signedEntryTimestamp"].as_str().unwrap().to_string(),
        inclusion_proof: serde_json::to_vec(&data["inclusionProof"]).unwrap(),
        integrated_time: data["integratedTime"].as_str().unwrap().to_string(),
    };

    println!("\n🔐 Testing with recent production Rekor entry");
    println!("UUID: {}", entry.uuid);
    println!("Log Index: {}", entry.log_index);
    println!("Integrated Time: {}", entry.integrated_time);

    let keyring = RekorKeyring::from_embedded_trust_root()
        .expect("Failed to load Rekor keyring");

    println!("\n⏳ Verifying SET signature...");
    keyring.verify_set(&entry)
        .expect("SET verification should pass");
    println!("✅ SET verified!");

    println!("\n⏳ Verifying inclusion proof...");
    keyring.verify_inclusion_proof(&entry)
        .expect("Inclusion proof verification should pass");
    println!("✅ Inclusion proof verified!");
}
EOF

echo "   ✅ Saved test code to: $TEST_DIR/test_snippet.rs"
echo ""

# Step 6: Display summary
echo "✅ SUCCESS! Recent Rekor entry fetched"
echo "======================================"
echo ""
echo "📊 Test Data Summary:"
echo "   Log Index:        $LOG_INDEX"
echo "   UUID:             $UUID"
echo "   Integrated Time:  $INTEGRATED_TIME_RFC3339 ($INTEGRATED_TIME)"
echo "   Log ID:           $LOG_ID"
echo ""
echo "📁 Generated Files:"
echo "   Rekor entry:      $REKOR_ENTRY_FILE"
echo "   Pretty JSON:      $TEST_DIR/recent_rekor_entry_pretty.json"
echo "   Rust test data:   $TEST_DATA_FILE"
echo "   Test code:        $TEST_DIR/test_snippet.rs"
echo ""
echo "🔍 Next Steps:"
echo "   1. Review the test data in: $TEST_DATA_FILE"
echo "   2. Copy the test code from: $TEST_DIR/test_snippet.rs"
echo "   3. Add to: src/lib/src/signature/keyless/rekor_verifier.rs"
echo "   4. Run: cargo test test_verify_recent_rekor_entry -- --nocapture"
