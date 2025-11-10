# Memory Profiling Guide for wsc

## Overview

This guide covers memory profiling options for the wsc project across different platforms.

## ByteHound (Linux Only - Recommended for CI)

**ByteHound** is the most comprehensive memory profiler for Rust, but only works on Linux.

### Running in GitHub Actions CI

We have a dedicated workflow for ByteHound profiling:

```bash
# Trigger manually via GitHub UI
# Or automatically on PRs that modify Rust code
```

After the workflow runs:
1. Download the `bytehound-profiles` artifact
2. Install ByteHound locally (on Linux)
3. Run: `bytehound server memory-profiling_*.dat`
4. Open http://localhost:8080

### Running via Docker (macOS/Windows)

```bash
# Build Docker image with ByteHound
docker build -f Dockerfile.bytehound -t wsc-bytehound .

# Run tests with profiling
docker run --rm -v $(pwd)/profiles:/workspace/profiles wsc-bytehound

# Copy profiling data out
docker cp <container_id>:/workspace/memory-profiling_*.dat ./profiles/

# View results (requires ByteHound installed locally on Linux or in Docker)
docker run --rm -p 8080:8080 -v $(pwd)/profiles:/data wsc-bytehound \
  bytehound server /data/memory-profiling_*.dat
```

Then open http://localhost:8080

## dhat-rs (Cross-Platform Alternative)

**dhat-rs** works on all platforms including macOS. It's less powerful than ByteHound but requires minimal changes.

### Installation

Add to `Cargo.toml`:

```toml
[dev-dependencies]
dhat = "0.3"
```

### Usage in Tests

Create a test file `tests/memory_profile.rs`:

```rust
#[cfg(test)]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[test]
fn profile_keyless_signing() {
    let _profiler = dhat::Profiler::new_heap();

    // Your test code here
    // Example: Test keyless signing flow

    // Profile data written to dhat-heap.json on drop
}
```

Run the test:

```bash
cargo test --test memory_profile

# View results
dh_view.html dhat-heap.json
```

### Integration Example

Add to existing tests in `src/lib/src/signature/keyless/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(feature = "dhat-heap", global_allocator)]
    fn test_with_profiling() {
        #[cfg(feature = "dhat-heap")]
        let _profiler = dhat::Profiler::new_heap();

        // Your test code
    }
}
```

## Instruments (macOS Native)

**Instruments** is Apple's profiling tool and works great on macOS.

### Installation

```bash
cargo install cargo-instruments
```

### Usage

```bash
# Profile a specific test
cargo instruments --release --test keyless_integration \
  --template Allocations -- --nocapture

# Profile the CLI
cargo instruments --release --bin wsc \
  --template Allocations -- sign --keyless test.wasm
```

### Available Templates

- `Allocations` - Memory allocations
- `Leaks` - Memory leaks
- `Time Profiler` - CPU profiling
- `System Trace` - System-level profiling

Results open automatically in Instruments.app

## Recommendations by Use Case

### Development (macOS)

**Best:** Use Instruments via `cargo-instruments`
- Native macOS tool
- Great visualization
- Easy to use
- No code changes needed

```bash
cargo install cargo-instruments
cargo instruments --template Allocations --bin wsc
```

### CI/CD (Linux)

**Best:** Use ByteHound in GitHub Actions
- Most comprehensive profiling
- Automated on PRs
- Artifacts for later analysis

### Cross-Platform (All OSes)

**Best:** Use dhat-rs
- Works everywhere
- Good for regression testing
- Integrates with tests
- Lightweight

```toml
[dev-dependencies]
dhat = "0.3"
```

## Example: Finding Memory Leaks

### Using ByteHound (Linux/Docker)

```bash
# Run with profiling
LD_PRELOAD=/path/to/libbytehound.so cargo test

# Analyze
bytehound server memory-profiling_*.dat

# Look for:
# - Leaked allocations (not freed before exit)
# - Large allocations
# - Allocation hotspots
```

### Using dhat-rs (macOS/All)

```rust
#[test]
fn check_for_leaks() {
    let _profiler = dhat::Profiler::new_heap();

    // Test code that might leak
    for _ in 0..1000 {
        keyless_sign_operation();
    }

    // dhat will report allocations on drop
}
```

### Using Instruments (macOS)

```bash
# Profile for leaks
cargo instruments --template Leaks --bin wsc -- sign test.wasm

# Instruments will show:
# - Leaked memory blocks
# - Stack traces of leaks
# - Memory graph
```

## Continuous Integration Setup

### GitHub Actions

The `.github/workflows/memory-profile.yml` workflow:
- Runs on PRs that modify Rust code
- Builds and runs tests with ByteHound
- Uploads profiling data as artifacts
- Provides instructions in summary

### Local Docker Setup

```bash
# Build once
docker build -f Dockerfile.bytehound -t wsc-bytehound .

# Run profiling
./scripts/profile-memory.sh

# View results
./scripts/view-profile.sh
```

## Common Profiling Scenarios

### 1. Profile Rekor Verification

```rust
#[test]
fn profile_rekor_verification() {
    let _profiler = dhat::Profiler::new_heap();

    // Load entry
    let entry = load_test_entry();

    // Profile verification
    for _ in 0..100 {
        verify_checkpoint(&entry).unwrap();
    }
}
```

### 2. Profile WASM Signature Operations

```bash
cargo instruments --template Allocations -- \
  cargo test test_signature_verification --release
```

### 3. Find Allocation Hotspots

```bash
# With ByteHound (Linux)
LD_PRELOAD=./libbytehound.so cargo bench

# With Instruments (macOS)
cargo instruments --template Allocations -- cargo bench
```

## Interpreting Results

### ByteHound UI

- **Allocations Tab**: See all allocations, sorted by size/count
- **Flame Graph**: Visual representation of allocation call stacks
- **Leaked Memory**: Filter for memory not freed
- **Timeline**: See allocation patterns over time

### dhat-rs Output

```
dhat: Total:     1,024 bytes in 10 blocks
dhat: At t-gmax: 512 bytes in 5 blocks
dhat: Leaked:    0 bytes in 0 blocks
```

- `Total`: All allocations during run
- `At t-gmax`: Peak memory usage
- `Leaked`: Memory not freed

### Instruments

- Red bars: Memory leaks
- Allocation list: Sorted by size
- Call trees: Where allocations happen
- Generations: Object lifecycle

## Best Practices

1. **Profile in Release Mode**: `cargo test --release` gives realistic results
2. **Use Consistent Workloads**: Same operations for comparison
3. **Profile Multiple Times**: Results can vary
4. **Focus on Hot Paths**: Profile critical code paths (keyless signing, verification)
5. **Track Over Time**: Compare before/after changes

## Further Reading

- [ByteHound Documentation](https://github.com/koute/bytehound)
- [dhat-rs Documentation](https://docs.rs/dhat/)
- [Rust Performance Book - Profiling](https://nnethercote.github.io/perf-book/profiling.html)
- [cargo-instruments](https://github.com/cmyr/cargo-instruments)
