#!/bin/bash
# Update Rekor test data with fresh entries from production
#
# This script fetches fresh Rekor entries and their inclusion proofs
# to update the hardcoded test data in rekor_verifier.rs

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

REKOR_URL="https://rekor.sigstore.dev"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Rekor Test Data Updater${NC}"
echo -e "${BLUE}========================================${NC}"

# Check dependencies
if ! command -v curl &> /dev/null; then
    echo -e "${RED}Error: curl is required but not installed${NC}"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is required but not installed${NC}"
    echo -e "${YELLOW}Install with: sudo apt-get install jq (or brew install jq on macOS)${NC}"
    exit 1
fi

echo -e "\n${YELLOW}Step 1: Fetching latest Rekor log info...${NC}"
LOG_INFO=$(curl -s "${REKOR_URL}/api/v1/log")
TREE_SIZE=$(echo "$LOG_INFO" | jq -r '.treeSize')
echo -e "${GREEN}✅ Current tree size: ${TREE_SIZE}${NC}"

# Fetch logIndex 0 (first entry) for historical test
echo -e "\n${YELLOW}Step 2: Fetching logIndex 0 (first entry)...${NC}"
ENTRY_0_UUID="362f8ecba72f4326b08416d417acdb0610d4a030d8f697f9d0a718024681a00fa0b9ba67072a38b5"
ENTRY_0_DATA=$(curl -s "${REKOR_URL}/api/v1/log/entries/${ENTRY_0_UUID}")

# Extract fields for logIndex 0
ENTRY_0_BODY=$(echo "$ENTRY_0_DATA" | jq -r ".[] | .body")
ENTRY_0_LOG_ID=$(echo "$ENTRY_0_DATA" | jq -r ".[] | .verification.inclusionProof.logID // \"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d\"")
ENTRY_0_INCLUSION=$(echo "$ENTRY_0_DATA" | jq -c ".[] | .verification.inclusionProof")
ENTRY_0_SET=$(echo "$ENTRY_0_DATA" | jq -r ".[] | .verification.signedEntryTimestamp")
ENTRY_0_TIME=$(echo "$ENTRY_0_DATA" | jq -r ".[] | .integratedTime")

echo -e "${GREEN}✅ Fetched logIndex 0 data${NC}"

# Fetch a recent entry (use the latest minus a small offset for safety)
RECENT_INDEX=$((TREE_SIZE - 1000))
echo -e "\n${YELLOW}Step 3: Fetching recent entry at logIndex ~${RECENT_INDEX}...${NC}"

# Get log entry by index
RECENT_ENTRY_DATA=$(curl -s "${REKOR_URL}/api/v1/log/entries?logIndex=${RECENT_INDEX}")
RECENT_UUID=$(echo "$RECENT_ENTRY_DATA" | jq -r 'keys[0]')

if [ -z "$RECENT_UUID" ] || [ "$RECENT_UUID" = "null" ]; then
    echo -e "${RED}Failed to fetch recent entry${NC}"
    exit 1
fi

# Extract fields for recent entry
RECENT_BODY=$(echo "$RECENT_ENTRY_DATA" | jq -r ".[] | .body")
RECENT_LOG_INDEX=$(echo "$RECENT_ENTRY_DATA" | jq -r ".[] | .logIndex")
RECENT_LOG_ID=$(echo "$RECENT_ENTRY_DATA" | jq -r ".[] | .verification.inclusionProof.logID")
RECENT_INCLUSION=$(echo "$RECENT_ENTRY_DATA" | jq -c ".[] | .verification.inclusionProof")
RECENT_SET=$(echo "$RECENT_ENTRY_DATA" | jq -r ".[] | .verification.signedEntryTimestamp")
RECENT_TIME=$(echo "$RECENT_ENTRY_DATA" | jq -r ".[] | .integratedTime")

echo -e "${GREEN}✅ Fetched logIndex ${RECENT_LOG_INDEX} (UUID: ${RECENT_UUID})${NC}"

# Generate Rust code
echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}  Generated Test Data (Rust code)${NC}"
echo -e "${BLUE}========================================${NC}"

cat << EOF

// ========== logIndex 0 (First Entry) ==========
let entry_0 = RekorEntry {
    uuid: "${ENTRY_0_UUID}".to_string(),
    log_index: 0,
    body: "${ENTRY_0_BODY}".to_string(),
    log_id: "${ENTRY_0_LOG_ID}".to_string(),
    inclusion_proof: serde_json::to_vec(&serde_json::json!(
        ${ENTRY_0_INCLUSION}
    )).unwrap(),
    signed_entry_timestamp: "${ENTRY_0_SET}".to_string(),
    integrated_time: "$(date -d @${ENTRY_0_TIME} -Iseconds 2>/dev/null || date -r ${ENTRY_0_TIME} -Iseconds 2>/dev/null || echo "2021-01-12T11:53:27Z")".to_string(),
};

// ========== logIndex ${RECENT_LOG_INDEX} (Recent Entry) ==========
let recent_entry = RekorEntry {
    uuid: "${RECENT_UUID}".to_string(),
    log_index: ${RECENT_LOG_INDEX},
    body: "${RECENT_BODY}".to_string(),
    log_id: "${RECENT_LOG_ID}".to_string(),
    inclusion_proof: serde_json::to_vec(&serde_json::json!(
        ${RECENT_INCLUSION}
    )).unwrap(),
    signed_entry_timestamp: "${RECENT_SET}".to_string(),
    integrated_time: "$(date -d @${RECENT_TIME} -Iseconds 2>/dev/null || date -r ${RECENT_TIME} -Iseconds 2>/dev/null)".to_string(),
};

EOF

echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}  Next Steps${NC}"
echo -e "${YELLOW}========================================${NC}"
echo "1. Copy the generated Rust code above"
echo "2. Update the test data in: src/lib/src/signature/keyless/rekor_verifier.rs"
echo "3. Replace the RekorEntry structs in both test functions"
echo "4. Update the 'fetched' date comments to: $(date -I)"
echo "5. Run: cargo test --test signature::keyless::rekor_verifier::tests -- --ignored"
echo ""
echo -e "${GREEN}Done!${NC}"
