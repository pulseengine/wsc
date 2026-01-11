# Loom + WSC Integration Guide

End-to-end supply chain attestation for WebAssembly optimization.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  LOOM (Optimizer)                                               │
│  Creates unsigned transformation attestation                    │
│  Dependency: wsc-attestation (lightweight, no crypto)           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  WSC (Signing)                                                  │
│  Signs module + attestation together                            │
│  • Local/Test: wsc sign -k secret.key                           │
│  • CI/Prod:    wsc sign --keyless (Sigstore)                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  WSC (Verification)                                             │
│  Verifies against TOML policy                                   │
│  wsc verify-chain --policy production.toml                      │
└─────────────────────────────────────────────────────────────────┘
```

## Loom Side: Create Attestation

### Cargo.toml

```toml
[dependencies]
# Lightweight - no crypto dependencies
wsc-attestation = "0.4"
```

### Code

```rust
use wsc_attestation::*;

pub fn optimize_with_attestation(input: &[u8], input_name: &str) -> (Vec<u8>, String) {
    // 1. Perform optimization
    let output = perform_optimization(input);

    // 2. Create UNSIGNED attestation (wsc will sign later)
    let attestation = TransformationAttestationBuilder::new_optimization("loom", env!("CARGO_PKG_VERSION"))
        .add_input_unsigned(input, input_name)
        .add_parameter("opt_level", serde_json::json!("aggressive"))
        .add_parameter("passes", serde_json::json!(["dead-code", "inlining", "mem2reg"]))
        .build(&output, "optimized.wasm");

    // 3. Return output + attestation JSON
    let json = attestation.to_json().expect("serialization failed");
    (output, json)
}

// Embed attestation in WASM custom section
pub fn embed_attestation(wasm: &[u8], attestation_json: &str) -> Vec<u8> {
    // Using wasm-encoder (you likely already have this)
    use wasm_encoder::{Module, CustomSection, RawSection};

    let mut module = Module::new();
    // ... copy existing sections ...

    // Add attestation section
    module.section(&CustomSection {
        name: std::borrow::Cow::Borrowed("wsc.transformation.attestation"),
        data: std::borrow::Cow::Borrowed(attestation_json.as_bytes()),
    });

    module.finish()
}
```

## WSC Side: Sign & Verify

### Local Development (Key-based)

```bash
# One-time: Generate test keypair
wsc keygen -k test-secret.key -K test-public.key

# Sign with key (SLSA L2)
loom optimize input.wasm -o output.wasm
wsc sign -i output.wasm -o output.wasm -k test-secret.key

# Verify
wsc verify-chain -i output.wasm --policy examples/policies/development.toml
```

### CI/Production (Keyless - No Secrets!)

```yaml
# .github/workflows/build.yml
name: Build and Sign
on: [push]

permissions:
  id-token: write  # Required for OIDC token
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install tools
        run: |
          cargo install loom
          cargo install wsc-cli

      - name: Build and optimize
        run: |
          cargo build --target wasm32-wasip2
          loom optimize target/wasm32-wasip2/release/app.wasm -o app-optimized.wasm

      - name: Sign with Sigstore (keyless)
        run: wsc sign -i app-optimized.wasm -o app-optimized.wasm --keyless

      - name: Verify against policy
        run: wsc verify-chain -i app-optimized.wasm --policy policy.toml

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: signed-wasm
          path: app-optimized.wasm
```

## SLSA Levels Achieved

| Environment | Signing Method | SLSA Level | Why |
|-------------|---------------|------------|-----|
| Local dev | `--key` | L2 | Signed provenance |
| CI | `--keyless` | L3 | Transparency log + non-forgeable identity |
| CI + all inputs signed | `--keyless` | L4 | Hermetic build |

## Policy Files

### Local Development
```toml
# development.toml - permissive for testing
[policy]
name = "development"
enforcement = "report"  # Warnings only

[slsa]
minimum_level = 1  # Just need attestation to exist
```

### Production
```toml
# production.toml - strict for deployment
[policy]
name = "production"
enforcement = "strict"

[slsa]
minimum_level = 3  # Require transparency log

[signatures]
require_attestation_signatures = true
max_attestation_age_days = 7

[trusted_tools.loom]
min_version = "0.1.0"

[trusted_tools.loom.keyless]
oidc_issuers = ["https://token.actions.githubusercontent.com"]
subjects = ["https://github.com/aspect-build/loom/.github/workflows/*"]
```

## Full Pipeline Example

```bash
# === PRODUCER (Loom in CI) ===

# 1. Optimize (creates unsigned attestation)
loom optimize component.wasm -o component-opt.wasm

# 2. Sign keylessly (OIDC identity from GitHub)
wsc sign -i component-opt.wasm -o component-opt.wasm --keyless

# 3. Show what we created
wsc show-chain -i component-opt.wasm
# Output:
#   Transformation: optimization by loom v0.1.0
#   Input: component.wasm (sha256:abc...)
#   Output: component-opt.wasm (sha256:def...)
#   Signature: keyless (identity: github.com/aspect-build/loom/...)
#   Rekor: https://rekor.sigstore.dev/api/v1/log/entries/...

# === CONSUMER (Verification) ===

# 4. Verify before deployment
wsc verify-chain -i component-opt.wasm --policy production.toml
# Output:
#   Policy: production v1.0
#   SLSA Level: SLSA L3
#
#   Rule Results:
#     ✓ slsa.minimum_level: Detected SLSA L3 meets requirement
#     ✓ signatures.attestation: Signed with keyless (identity: github.com/...)
#     ✓ trusted_tools.loom: Tool 'loom' version 0.1.0 is trusted
#
#   ✓ Policy evaluation PASSED
```

## Summary

| Component | Responsibility | Dependencies |
|-----------|---------------|--------------|
| **Loom** | Create attestation, embed in WASM | `wsc-attestation` (lightweight) |
| **WSC CLI** | Sign (key or keyless), verify | Full `wsc` |
| **Policy** | Define trust requirements | TOML file |

Loom stays lightweight. WSC handles all the crypto complexity.
