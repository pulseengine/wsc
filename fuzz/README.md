# Fuzz Testing for wsc

This directory contains fuzz targets for security-critical parsing code in wsc.

## Overview

Fuzz testing automatically generates random/mutated inputs to find crashes, panics,
and logic errors that manual testing misses. This is essential for code that handles
untrusted input like signatures, certificates, and WASM modules.

## Prerequisites

Install cargo-fuzz (requires nightly Rust):

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Ensure you have a nightly toolchain
rustup install nightly
```

## Fuzz Targets

| Target | Description | Security Focus |
|--------|-------------|----------------|
| `fuzz_varint` | LEB128 varint decoding | Integer overflow, infinite loops |
| `fuzz_keyless_signature` | KeylessSignature::from_bytes | Buffer overflow, UTF-8 validation |
| `fuzz_module_parsing` | WASM module deserialization | Memory exhaustion, truncated input |
| `fuzz_signature_data` | Signature data structures | Array bounds, count validation |
| `fuzz_public_key` | Key format parsing (PEM/DER/OpenSSH) | Format confusion, malformed keys |
| `fuzz_rekor_entry` | Rekor JSON entry parsing | JSON injection, deeply nested objects |

## Running Fuzz Tests

### Quick Start

```bash
cd fuzz

# Run a specific fuzz target (Ctrl+C to stop)
cargo +nightly fuzz run fuzz_varint

# Run with timeout (5 minutes)
cargo +nightly fuzz run fuzz_varint -- -max_total_time=300

# List all available targets
cargo +nightly fuzz list
```

### With Corpus (Recommended)

Using a corpus of valid inputs helps the fuzzer find more bugs:

```bash
# Create corpus directories
mkdir -p corpus/fuzz_varint
mkdir -p corpus/fuzz_keyless_signature
mkdir -p corpus/fuzz_module_parsing

# Add seed files (optional but recommended)
# Copy valid .wasm files to corpus/fuzz_module_parsing/
# Copy valid signatures to corpus/fuzz_keyless_signature/

# Run with corpus
cargo +nightly fuzz run fuzz_module_parsing corpus/fuzz_module_parsing
```

### Analyzing Crashes

When a crash is found, it will be saved to `artifacts/<target>/`:

```bash
# View crash details
cargo +nightly fuzz run fuzz_varint artifacts/fuzz_varint/crash-<hash>

# Minimize the crash input (find smallest reproducer)
cargo +nightly fuzz tmin fuzz_varint artifacts/fuzz_varint/crash-<hash>

# Minimize the corpus (remove redundant inputs)
cargo +nightly fuzz cmin fuzz_varint corpus/fuzz_varint
```

### Coverage Analysis

```bash
# Generate coverage report
cargo +nightly fuzz coverage fuzz_varint

# View coverage in browser (requires cargo-cov)
cargo +nightly fuzz coverage fuzz_varint --html
```

## Continuous Fuzzing

### Local (overnight/weekend)

```bash
# Run all targets in parallel
for target in $(cargo +nightly fuzz list); do
    cargo +nightly fuzz run $target -- -max_total_time=3600 &
done
wait
```

### CI Integration

See `.github/workflows/fuzz.yml` for GitHub Actions integration:

```yaml
name: Fuzzing
on:
  schedule:
    - cron: '0 0 * * *'  # Daily
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        target: [fuzz_varint, fuzz_keyless_signature, fuzz_module_parsing]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz
      - run: cargo +nightly fuzz run ${{ matrix.target }} -- -max_total_time=300
      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: fuzz-crash-${{ matrix.target }}
          path: fuzz/artifacts/
```

## Expected Findings

Based on the codebase structure, potential issues include:

1. **Varint decoding**: Integer overflows on large values, infinite loops on malformed continuation bytes
2. **Keyless signatures**: UTF-8 validation bypass in certificate PEM, JSON parsing issues in Rekor entry
3. **Module parsing**: Memory exhaustion via large section lengths, truncated input handling
4. **Signature data**: Array index out of bounds when exceeding MAX_HASHES/MAX_SIGNATURES
5. **Public keys**: Format confusion between PEM/DER/OpenSSH, invalid key material

## Reporting Vulnerabilities

If you find a security issue:

1. **DO NOT** open a public issue
2. Report privately via GitHub Security Advisories
3. Include the crash input and reproduction steps
4. Allow time for a fix before public disclosure

## Resources

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [Rust fuzzing book](https://rust-fuzz.github.io/book/)
- [Google OSS-Fuzz](https://github.com/google/oss-fuzz) for continuous fuzzing
