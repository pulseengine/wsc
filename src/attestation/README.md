# wsc-attestation

Minimal crate providing transformation attestation types for WebAssembly toolchains.

## Purpose

When WebAssembly modules are transformed (optimized, composed, instrumented), original signatures become invalid because the binary hash changes. This crate provides the data structures to maintain cryptographic audit trails through transformation pipelines.

```
Component A (signed) ──┐
                       ├──→ WAC Compose ──→ Loom Optimize ──→ Final Binary
Component B (signed) ──┘                                          │
                                                                  ▼
                                                    Audit trail preserved!
```

## Design Philosophy

This crate is intentionally **minimal** (~6 dependencies) so that tools like optimizers and composers can add attestations without pulling in heavy cryptographic dependencies.

- **No WASM parsing** - Tools use their own (wasmparser, wasm-encoder, etc.)
- **No signing** - Just data structures; tools sign their own way
- **Serde-based** - JSON serialization for embedding in WASM custom sections

## Usage

```rust
use wsc_attestation::*;

// Create an attestation for an optimization
let attestation = TransformationAttestationBuilder::new_optimization("loom", "0.1.0")
    .add_input_unsigned(&input_bytes, "input.wasm")
    .add_parameter("opt_level", serde_json::json!("aggressive"))
    .build(&output_bytes, "output.wasm");

// Serialize to JSON
let json = attestation.to_json().unwrap();

// Embed in WASM custom section using your preferred library
// Section name: "wsc.transformation.attestation"
your_wasm_lib::add_custom_section(
    &mut module,
    TRANSFORMATION_ATTESTATION_SECTION,
    json.as_bytes()
);
```

## Integration with WSC

This crate is part of the [WSC (WebAssembly Signature Component)](https://github.com/pulseengine/wsc) ecosystem:

- **wsc-attestation** (this crate): Attestation types for tools
- **wsc**: Full signing/verification library with WASM parsing
- **wsc-cli**: Command-line tool for signing and verification

## Section Names

| Constant | Value | Purpose |
|----------|-------|---------|
| `TRANSFORMATION_ATTESTATION_SECTION` | `wsc.transformation.attestation` | Single transformation attestation |
| `TRANSFORMATION_AUDIT_TRAIL_SECTION` | `wsc.transformation.audit_trail` | Full chain for multi-stage |

## License

MIT
