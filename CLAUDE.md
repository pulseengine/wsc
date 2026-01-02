# Claude Code Instructions for wsc

## Project Overview

wsc (WebAssembly Signature Component) is a **security-critical** cryptographic signing tool for WebAssembly modules. It handles:
- Ed25519 signatures
- Sigstore keyless signing (OIDC → Fulcio → Rekor)
- Air-gapped verification for embedded devices
- Trust bundle management

## Security-Critical Release Process

**THIS IS A CRYPTOGRAPHIC SECURITY TOOL. RELEASES MUST FOLLOW THIS PROCESS:**

### Pre-Release Checklist (MANDATORY)

1. **All changes via PR**: Never push directly to main for any code changes
2. **CI must pass completely**: Wait for ALL CI jobs to succeed before merging
3. **Watch the full CI run**: Do not assume CI passes - verify it
4. **Sign & Verify workflow must succeed**: The `wasm-signing.yml` workflow must demonstrate end-to-end signing and verification works

### Release Process

1. **Create version bump PR**:
   ```bash
   git checkout -b release/vX.Y.Z
   # Update version in Cargo.toml
   # Update internal dependency versions
   git commit -m "chore: bump version to X.Y.Z"
   git push -u origin release/vX.Y.Z
   gh pr create
   ```

2. **Wait for CI to complete**: Watch ALL checks pass
   ```bash
   gh pr checks <PR#> --watch
   ```

3. **Verify signing workflow**: Ensure the Sign WASM Module workflow succeeds and produces valid artifacts

4. **Merge PR**: Only after all checks pass
   ```bash
   gh pr merge <PR#> --squash
   ```

5. **Create release**: Only after merge and main CI passes
   ```bash
   # Pull latest main
   git checkout main && git pull

   # Verify main CI passed
   gh run list --branch main --limit 1

   # Create and push tag
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z

   # Create GitHub release
   gh release create vX.Y.Z --generate-notes
   ```

### What NOT to do

- **NEVER** release without CI verification
- **NEVER** push tags before PR is merged and CI passes
- **NEVER** assume CI will pass - always watch it complete
- **NEVER** skip the signing workflow verification
- **NEVER** release if any security-related test fails

## Build Commands

```bash
# Build
cargo build --release

# Test (all tests)
cargo test

# Test specific module
cargo test --test airgapped_e2e
cargo test --test keyless_integration -- --ignored  # Requires OIDC

# Bazel build
bazel build //src/lib:wsc
bazel build //src/component:signing_lib
bazel build //src/cli:wasmsign_cli
```

## Repository Structure

- `src/lib/` - Core signing library
- `src/cli/` - Command-line interface
- `src/component/` - WASM component (WASI)
- `src/lib/src/airgapped/` - Air-gapped verification
- `src/lib/src/keyless/` - Sigstore keyless signing
- `fuzz/` - Fuzz testing targets

## CI Workflows

- `rust.yml` - Main CI (cargo + bazel builds, tests)
- `wasm-signing.yml` - End-to-end signing demonstration
- `fuzz.yml` - Fuzz testing
- `memory.yml` - Memory profiling
