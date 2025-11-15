#!/bin/bash
# Example: Signing WASM components for composition with wac
#
# This demonstrates the current workflow for:
# 1. Owner signs individual components
# 2. Compose with wac
# 3. Integrator signs composed result
# 4. Verify all signatures
#
# Prerequisites:
# - wac CLI installed (cargo install wac-cli)
# - wsc CLI built (cargo build --release)
# - Certificate infrastructure set up

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== WASM Component Composition with Multi-Signature ===${NC}\n"

# Configuration
OWNER_CA="examples/certs/owner-root-ca.pem"
OWNER_CERT="examples/certs/owner-device-cert.pem"
OWNER_KEY="examples/keys/owner-device-key"

INTEGRATOR_CA="examples/certs/integrator-root-ca.pem"
INTEGRATOR_CERT="examples/certs/integrator-device-cert.pem"
INTEGRATOR_KEY="examples/keys/integrator-device-key"

# Component files
COMPONENT_A="examples/components/component-a.wasm"
COMPONENT_B="examples/components/component-b.wasm"

# Output files
SIGNED_A="examples/components/component-a.signed.wasm"
SIGNED_B="examples/components/component-b.signed.wasm"
COMPOSED="examples/composed/app.wasm"
DUAL_SIGNED="examples/composed/app.dual-signed.wasm"
MANIFEST="examples/composed/composition-manifest.json"

echo -e "${GREEN}Step 1: Owner signs individual components${NC}"
echo "Signing component A..."
target/release/wsc sign \
  --input "$COMPONENT_A" \
  --output "$SIGNED_A" \
  --certificate "$OWNER_CERT" \
  --ca "$OWNER_CA" \
  --key "$OWNER_KEY"

echo "Signing component B..."
target/release/wsc sign \
  --input "$COMPONENT_B" \
  --output "$SIGNED_B" \
  --certificate "$OWNER_CERT" \
  --ca "$OWNER_CA" \
  --key "$OWNER_KEY"

echo -e "${GREEN}✓ Both components signed by owner${NC}\n"

echo -e "${GREEN}Step 2: Compose with wac${NC}"
wac compose \
  --output "$COMPOSED" \
  "$SIGNED_A" \
  "$SIGNED_B"

echo -e "${GREEN}✓ Components composed${NC}\n"

echo -e "${GREEN}Step 3: Create composition manifest${NC}"
cat > "$MANIFEST" <<EOF
{
  "version": "1.0",
  "composition_tool": "wac $(wac --version | head -n1)",
  "composition_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "components": [
    {
      "id": "component-a",
      "path": "$COMPONENT_A",
      "hash": "$(sha256sum $COMPONENT_A | cut -d' ' -f1)",
      "signer": "CN=Owner Device, O=Owner Corp"
    },
    {
      "id": "component-b",
      "path": "$COMPONENT_B",
      "hash": "$(sha256sum $COMPONENT_B | cut -d' ' -f1)",
      "signer": "CN=Owner Device, O=Owner Corp"
    }
  ],
  "composition_hash": "$(sha256sum $COMPOSED | cut -d' ' -f1)"
}
EOF

echo -e "${GREEN}✓ Manifest created${NC}\n"
cat "$MANIFEST"
echo ""

echo -e "${GREEN}Step 4: Integrator signs composed component${NC}"
target/release/wsc sign \
  --input "$COMPOSED" \
  --output "$DUAL_SIGNED" \
  --certificate "$INTEGRATOR_CERT" \
  --ca "$INTEGRATOR_CA" \
  --key "$INTEGRATOR_KEY"

echo -e "${GREEN}✓ Composed component signed by integrator${NC}\n"

echo -e "${GREEN}Step 5: Verify all signatures${NC}"
target/release/wsc verify \
  --input "$DUAL_SIGNED" \
  --ca "$OWNER_CA" \
  --ca "$INTEGRATOR_CA" \
  --require-all \
  --verbose

echo -e "\n${GREEN}✓ All signatures verified!${NC}\n"

echo -e "${GREEN}Step 6: Inspect signatures${NC}"
target/release/wsc inspect "$DUAL_SIGNED"

echo -e "\n${YELLOW}=== Summary ===${NC}"
echo "Original components: $COMPONENT_A, $COMPONENT_B"
echo "Owner signatures: 2 (one per component)"
echo "Composition tool: wac"
echo "Integrator signature: 1 (on composed result)"
echo "Total signatures in final artifact: 3"
echo ""
echo "Final artifact: $DUAL_SIGNED"
echo "Manifest: $MANIFEST"
echo ""
echo -e "${GREEN}✓ Composition workflow complete!${NC}"
