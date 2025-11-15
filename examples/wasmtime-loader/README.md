# Wasmtime Component Loader with WSC Verification

This example demonstrates how to integrate [WSC](https://github.com/pulseengine/wsc) signature verification into a Wasmtime-based WebAssembly component loader.

## Quick Start

```bash
# 1. Build the component
cd examples/wasmtime-loader
wasm-tools component new components/hello.wat -o components/hello.wasm

# 2. Generate signing key
cargo run --bin wsc -- generate-key -o keys/signing-key

# 3. Sign the component
cargo run --bin wsc -- sign -k keys/signing-key components/hello.wasm

# 4. Extract public key for verification
cargo run --bin wsc -- export-public-key -k keys/signing-key -o keys/trusted.pub

# 5. Run the loader (verifies signature before loading)
cargo run --release -- components/hello.wasm
```

## Verification Modes

### Strict Mode (Recommended for Production)

Requires a valid signature from a trusted key. Fails if signature is missing or invalid.

```bash
cargo run -- --strict components/hello.wasm
```

**Use case:** Production deployments where only signed components should run.

### Lenient Mode (Development)

Warns if signature is missing/invalid but loads the component anyway.

```bash
cargo run -- --lenient components/hello.wasm
```

**Use case:** Development environments where you want visibility into signing status without blocking execution.

### No Verification (Not Recommended)

Skips signature verification entirely.

```bash
cargo run -- --no-verify components/hello.wasm
```

**Use case:** Testing, debugging, or when signature verification is handled elsewhere.

## Integration Pattern

The key integration code is in `src/main.rs`:

```rust
use wsc::signature::PublicKeySet;
use wasmtime::component::Component;

// Load trusted keys
let mut keys = PublicKeySet::empty();
keys.insert_from_file("keys/trusted.pub")?;

// Read component bytes
let bytes = std::fs::read("component.wasm")?;

// Verify signature
keys.verify(&bytes)?;

// Parse component (only after verification passes)
let component = Component::new(&engine, &bytes)?;
```

## Trust Configuration

### Loading Keys from Files

```rust
let mut keys = PublicKeySet::empty();
keys.insert_from_file("trusted-key.pub")?;
```

### Loading Keys from Environment

```rust
if let Ok(key_pem) = std::env::var("TRUSTED_PUBLIC_KEY") {
    keys.insert_from_pem(&key_pem)?;
}
```

### Multiple Trusted Keys

```rust
let mut keys = PublicKeySet::empty();
keys.insert_from_file("key1.pub")?;
keys.insert_from_file("key2.pub")?;
keys.insert_from_file("key3.pub")?;
// Component is valid if signed by ANY of these keys
```

## Performance Considerations

### Verification Cost

Signature verification requires:
- Reading entire component into memory
- Ed25519 signature verification (~50-100μs)
- SHA256 hashing of component bytes

For a 1MB component, expect ~2-5ms total verification overhead.

### Caching Verification Results

For production, cache verification results:

```rust
use std::collections::HashMap;
use sha2::{Sha256, Digest};

struct VerificationCache {
    verified: HashMap<[u8; 32], bool>,
}

impl VerificationCache {
    fn is_verified(&self, bytes: &[u8]) -> Option<bool> {
        let hash = Sha256::digest(bytes);
        self.verified.get(hash.as_slice()).copied()
    }

    fn mark_verified(&mut self, bytes: &[u8], valid: bool) {
        let hash = Sha256::digest(bytes);
        self.verified.insert(hash.into(), valid);
    }
}
```

### When to Verify

**Option 1: Verify at load time (recommended)**
- Verify once when component is first loaded
- Cache the parsed `Component` object
- No re-verification on each instantiation

**Option 2: Verify on first instantiation**
- Defer verification until component is actually used
- Useful for lazy loading scenarios

**Option 3: Verify at download/installation**
- Verify during component installation
- Skip verification at runtime
- Fastest runtime performance

## Error Handling

```rust
match keys.verify(&bytes) {
    Ok(_) => {
        log::info!("Signature verified");
        // Proceed with loading
    }
    Err(e) => {
        log::error!("Signature verification failed: {}", e);
        // Decide: fail hard or log and continue?
        if strict_mode {
            return Err(e.into());
        } else {
            log::warn!("Loading anyway (lenient mode)");
        }
    }
}
```

## Security Best Practices

1. **Use strict mode in production** - Only load signed components
2. **Protect private keys** - Use hardware security modules for signing keys
3. **Rotate keys regularly** - Have a key rotation policy
4. **Verify before parsing** - Don't parse untrusted bytecode
5. **Log verification failures** - Monitor for tampering attempts

## Comparison with Other Runtimes

### Wasmtime (this example)
```rust
let bytes = std::fs::read(path)?;
keys.verify(&bytes)?;
Component::new(&engine, &bytes)?
```

### wasmer
```rust
let bytes = std::fs::read(path)?;
keys.verify(&bytes)?;
wasmer::Module::new(&store, &bytes)?
```

### Custom Runtime
```rust
let bytes = std::fs::read(path)?;
keys.verify(&bytes)?;
// Parse with your runtime
```

The pattern is the same: **verify bytes before parsing**.

## Troubleshooting

### "No trusted keys found"

Generate and export a public key:
```bash
cargo run --bin wsc -- generate-key -o key
cargo run --bin wsc -- export-public-key -k key -o trusted.pub
```

### "Signature verification failed"

Check that:
1. Component is actually signed: `cargo run --bin wsc -- inspect component.wasm`
2. Public key matches signing key: `cargo run --bin wsc -- export-public-key -k signing-key`
3. Component hasn't been modified after signing

### "Component must have a valid signature"

Either:
- Sign the component: `cargo run --bin wsc -- sign -k key component.wasm`
- Use lenient mode: `cargo run -- --lenient component.wasm`

## See Also

- [WSC Documentation](../../README.md)
- [Wasmtime Component Model](https://docs.wasmtime.dev/lang-rust/component-model.html)
- [WebAssembly Component Model](https://github.com/WebAssembly/component-model)
