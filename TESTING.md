# Testing Guide for WSC

This document describes how to run tests locally and in CI.

## Quick Start

### Run All CI Tests Locally

```bash
./scripts/run-ci-tests.sh
```

This script runs all the same tests that run in CI:
- `cargo build` - Build all targets
- `cargo test` - Run all tests
- `cargo clippy` - Lint checks
- `cargo fmt --check` - Format checks

### Individual Test Commands

```bash
# Build the project
cargo build --verbose

# Run all tests
cargo test --verbose

# Run only library tests
cargo test --lib

# Run specific test file
cargo test --test keyless_integration

# Run with logging
RUST_LOG=debug cargo test -- --nocapture

# Run ignored tests (e.g., integration tests requiring OIDC)
cargo test --test keyless_integration -- --ignored --nocapture
```

## Pre-commit Hooks

We use pre-commit hooks to catch issues before they're committed.

### Setup

1. Install pre-commit:
   ```bash
   pip install pre-commit
   # or
   brew install pre-commit  # macOS
   # or
   sudo apt-get install pre-commit  # Ubuntu/Debian
   ```

2. Install the git hooks:
   ```bash
   pre-commit install
   ```

3. (Optional) Run on all files:
   ```bash
   pre-commit run --all-files
   ```

### What Gets Checked

The pre-commit hooks run:
- `cargo fmt` - Rust code formatting
- `cargo build` - Compilation check
- `cargo clippy` - Linting
- `cargo test` - Unit tests
- File checks (trailing whitespace, YAML/TOML syntax, etc.)
- Markdown linting

### Bypassing Pre-commit (Not Recommended)

If you need to commit without running hooks:
```bash
git commit --no-verify -m "message"
```

## CI Tests

Our GitHub Actions CI runs these workflows:

### 1. Rust CI (`.github/workflows/rust.yml`)

**Cargo Build & Test:**
- Runs on: Ubuntu, macOS
- Commands:
  - `cargo build --verbose`
  - `cargo test --verbose`

**Bazel Build:**
- Runs on: Ubuntu, macOS
- Builds:
  - Core library: `bazel build //src/lib:wsc`
  - Signing component: `bazel build //src/component:signing_lib`
  - CLI component: `bazel build //src/cli:wasmsign_cli`

**Keyless Integration Tests:**
- Runs on: Ubuntu
- Requires: OIDC token (GitHub Actions environment)
- Command: `cargo test --test keyless_integration -- --ignored --nocapture`

### 2. Memory Analysis (`.github/workflows/memory-profile.yml`)

**Allocation-Free Verification:**
- Tests which operations are allocation-free
- Command: `cargo test --features allocation-guard --test real_world_allocation_free -- --test-threads=1 --nocapture`

**ByteHound Profiling:**
- Generates detailed memory allocation profiles
- Requires: ByteHound binary (Linux only)
- Creates interactive web UI for analysis

## Known Test Issues

### Rekor Verification Tests (Ignored - Require Fresh Data)

Two tests in `signature::keyless::rekor_verifier::tests` are marked `#[ignore]`:
- `test_verify_real_production_rekor_entry`
- `test_verify_fresh_rekor_entry_with_current_proof`

**Why Ignored:** These tests use hardcoded Rekor entry data with Merkle tree inclusion proofs that become stale as the Rekor log grows.

**Running These Tests:**
```bash
# Option 1: Run locally with environment variable
RUN_IGNORED_TESTS=true ./scripts/run-ci-tests.sh

# Option 2: Run directly with cargo
cargo test signature::keyless::rekor_verifier::tests -- --ignored --nocapture
```

**Updating Test Data:**
```bash
# Step 1: Fetch fresh data from Rekor API
./scripts/update-rekor-test-data.sh

# Step 2: Copy the generated Rust code into rekor_verifier.rs
# (Follow the instructions in the script output)

# Step 3: Verify tests pass
cargo test signature::keyless::rekor_verifier::tests -- --ignored --nocapture
```

**In CI:** These tests run automatically in the `rekor-verification` job, which fetches fresh data and runs with `continue-on-error: true` to avoid blocking builds when data is stale.

**When to Update:** When the Rekor log has grown significantly (every few months) or when developing Rekor verification features.

**Alternative:** The integration tests in `keyless_integration.rs` fetch LIVE Rekor data during signing and verify it, providing real-world validation without hardcoded data.

### Allocation-Guard Tests

The allocation-guard tests intentionally panic (SIGABRT) when allocations occur in locked phases. This is expected behavior for the phase-locked allocator.

**Running successfully:**
```bash
cargo test --features allocation-guard --test real_world_allocation_free \
  -- test_ed25519_signature_verification_raw --test-threads=1 --nocapture
```

**Expected output:**
```
✅ ALLOCATION-FREE! Ed25519 verification succeeded without allocations
```

## Test Organization

```
src/lib/
├── src/
│   ├── lib.rs              # Unit tests in each module
│   ├── signature/
│   │   └── keyless/        # Keyless signing tests
│   └── ...
└── tests/
    ├── keyless_integration.rs      # Integration tests (some require OIDC)
    ├── allocation_free.rs          # Simple allocation tests
    └── real_world_allocation_free.rs # Real-world allocation benchmarks
```

## Test Coverage

Current test status after rebase:
- **Total Tests:** 376
- **Passing:** 374 (99.5%)
- **Failing:** 2 (Rekor verification - known issue)
- **Ignored:** Integration tests requiring OIDC environment

## Debugging Failed Tests

### View test output with details:
```bash
cargo test -- --nocapture --test-threads=1
```

### Run specific failing test:
```bash
cargo test signature::keyless::rekor_verifier::tests::test_verify_real_production_rekor_entry -- --nocapture
```

### Enable debug logging:
```bash
RUST_LOG=debug cargo test -- --nocapture
```

## Performance Testing

### Memory Profiling with ByteHound (Linux only)

1. Install ByteHound:
   ```bash
   wget https://github.com/koute/bytehound/releases/download/0.11.0/bytehound-x86_64-unknown-linux-gnu.tgz
   tar xzf bytehound-x86_64-unknown-linux-gnu.tgz
   mv bytehound libbytehound.so ~/.cargo/bin/
   ```

2. Run tests with profiling:
   ```bash
   LD_PRELOAD=~/.cargo/bin/libbytehound.so cargo test --release
   ```

3. View results:
   ```bash
   bytehound server memory-profiling_*.dat
   # Open http://localhost:8080
   ```

## Continuous Integration

CI runs automatically on:
- Push to `main` branch
- Pull requests to `main`
- Manual workflow dispatch

View CI results: https://github.com/pulseengine/wsc/actions
