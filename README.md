# wsc - WebAssembly Signature Component

**Sign in the cloud. Verify anywhere.**

A tool and library for signing WebAssembly modules with embedded signatures that can be verified completely offline - perfect for embedded systems, edge devices, and air-gapped environments.

## Why wsc?

Unlike OCI registry signatures (Cosign) that require network access at verification time, wsc embeds signatures directly in the WASM module. This enables:

| Scenario | Cosign/OCI | wsc |
|----------|------------|-----|
| IoT device with intermittent WiFi | Needs connectivity | Verify offline |
| Industrial controller | Requires registry access | Signature embedded |
| Edge CDN node | Registry latency | Local verification |
| Air-gapped network | Cannot verify | Works offline |

## About

**wsc** is an enhanced WebAssembly signing toolkit built on the foundation of [wasmsign2](https://github.com/wasm-signatures/wasmsign2) by Frank Denis. While maintaining compatibility with the WebAssembly modules signatures proposal, wsc adds production-oriented features:

- **Offline-First Verification**: Embedded signatures survive distribution - no network required at runtime
- **Keyless Signing**: Full Sigstore/Fulcio/Rekor integration with OIDC authentication (GitHub Actions, Google Cloud, GitLab CI)
- **Keyless Verification**: Verify Sigstore signatures offline with certificate chain and SET validation
- **Enhanced Rekor Verification**: Checkpoint-based verification with security hardening
- **Bazel Integration**: Full BUILD and MODULE.bazel support for hermetic builds
- **WIT Component Model**: Both library (`wsc-component.wasm`) and CLI (`wsc-cli.wasm`) builds

## About This Project

**wsc** is based on [wasmsign2](https://github.com/wasm-signatures/wasmsign2) by Frank Denis, a reference implementation of the [WebAssembly modules signatures proposal](https://github.com/wasm-signatures/design).

We plan to add additional features to support production use cases, including:

- Enhanced Rekor verification with checkpoint-based proofs
- Bazel build system integration for hermetic builds
- WebAssembly Component Model (WIT) support
- Expanded keyless signing capabilities
- Additional security hardening and validation

MIT License - Original wasmsign2 Copyright (c) 2024 Frank Denis

## WASM Signatures

Unlike typical desktop and mobile applications, WebAssembly binaries do not embed any kind of digital signatures to verify that they come from a trusted source, and haven't been tampered with.

wsc takes an existing WebAssembly module, computes a signature for its content, and stores the signature in a custom section.

The resulting binary remains a standalone, valid WebAssembly module, but signatures can be verified prior to executing it.

wsc implements the [WebAssembly modules signatures](https://github.com/wasm-signatures/design) proposal.
The file format is documented in the [WebAssembly tool conventions repository](https://github.com/WebAssembly/tool-conventions/blob/main/Signatures.md).

The proposal, and this implementation, support domain-specific features such as:

- The ability to have multiple signatures for a single module, with a compact representation
- The ability to sign a module which was already signed with different keys
- The ability to extend an existing module with additional custom sections, without invalidating existing signatures
- The ability to verify multiple subsets of a module's sections with a single signature
- The ability to turn an embedded signature into a detached one, and the other way round

## Installation

`wsc` is a Rust crate that can be used in other applications.

It is also a CLI tool to perform common operations, whose usage is summarized below.

### Using Cargo

```bash
cargo install wsc-cli
```

### From Source

```bash
git clone https://github.com/pulseengine/wsc.git
cd wsc
cargo build --release
```

### Using Bazel

```bash
bazel build //src/cli:wsc
```

## Usage

### Keyless Signing (Sigstore)

wsc supports keyless signing using [Sigstore](https://www.sigstore.dev/) - sign in CI, verify anywhere:

```bash
# Sign in GitHub Actions (or any OIDC-enabled CI)
wsc sign --keyless -i module.wasm -o signed.wasm
```

This will:
1. Authenticate via OIDC (GitHub Actions, Google Cloud, GitLab CI)
2. Generate an ephemeral key pair
3. Obtain a certificate from Fulcio
4. Sign the module
5. Upload signature to Rekor transparency log
6. Embed the certificate and Rekor proof in the module

### Keyless Verification (Offline)

Verify a keyless-signed module - no network required:

```bash
# Basic verification (offline)
wsc verify --keyless -i signed.wasm

# With identity constraints
wsc verify --keyless -i signed.wasm \
  --cert-identity "user@example.com" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com"
```

Verification performs:
1. Certificate chain validation against embedded Fulcio roots
2. Rekor SET (Signed Entry Timestamp) verification
3. Identity and issuer validation (optional)

### Traditional Key-Based Signing

#### Creating a Key Pair

```bash
wsc keygen -k secret.key -K public.key
```

#### Signing a Module

```bash
wsc sign -k secret.key -i module.wasm -o signed.wasm
```

#### Verifying a Module

```bash
wsc verify -K public.key -i signed.wasm
```

### Inspecting a Module

```bash
wsc show -i module.wasm
```

### Detaching/Attaching Signatures

```bash
# Detach signature to a file
wsc detach -i signed.wasm -o unsigned.wasm -S signature.bin

# Attach signature from a file
wsc attach -i unsigned.wasm -o signed.wasm -S signature.bin
```

### Partial Verification

wsc can verify signatures for specific custom sections:

```bash
wsc verify -K public.key -i signed.wasm --split "custom_section_regex"
```

### OpenSSH Keys Support

wsc supports OpenSSH-formatted Ed25519 keys:

```bash
# Generate SSH key
ssh-keygen -t ed25519 -f key

# Sign module (use --ssh flag)
wsc sign -k key --ssh -i module.wasm -o signed.wasm

# Verify module
wsc verify -K key.pub --ssh -i signed.wasm
```

### GitHub Integration

Verify using a GitHub user's SSH public keys:

```bash
wsc verify --from-github username -i signed.wasm
```

## Enhanced Features

### Rekor Verification

wsc includes comprehensive Rekor inclusion proof verification:

- ✅ **SET (Signed Entry Timestamp)** verification
- ✅ **Checkpoint-based verification** with cryptographic tree state proofs
- ✅ **Security hardening**: Key fingerprint validation, origin validation, cross-shard attack prevention
- ✅ **Defense-in-depth**: 5 layers of security validation

See [docs/checkpoint_security_audit.md](docs/checkpoint_security_audit.md) for details.

### Bazel Integration

Full Bazel support for hermetic builds:

```python
# BUILD.bazel
load("@rules_rust//rust:defs.bzl", "rust_binary")

rust_binary(
    name = "wsc",
    srcs = ["//src/cli:wsc"],
)
```

See [MODULE.bazel](MODULE.bazel) for dependency configuration.

### WebAssembly Component Model

Build both library and CLI as WebAssembly components:

```bash
# Build WIT component library
bazel build //src/component:wsc-component.wasm

# Build WASI CLI binary
bazel build //src/cli:wsc-cli.wasm
```

## Documentation

- [Checkpoint Implementation](docs/checkpoint_implementation.md) - Checkpoint-based verification details
- [Security Audit](docs/checkpoint_security_audit.md) - Security vulnerabilities found and fixed
- [Checkpoint Format](docs/rekor_checkpoint_format.md) - Complete format specification
- [sigstore-rs Comparison](docs/sigstore-rs_comparison.md) - Comparison with official Rust implementation
- [Security Documentation](SECURITY.md) - Comprehensive security model and operational security
- [Keyless Signing](docs/keyless.md) - Keyless signing with Sigstore/Fulcio
- [Testing Guide](docs/testing.md) - Testing procedures and guidelines

## Development Status

wsc is under active development. Core signing/verification and Rekor validation are functional. See [open issues](https://github.com/pulseengine/wsc/issues) for planned enhancements.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- **Frank Denis** - Original wasmsign2 implementation
- **Sigstore Project** - Keyless signing infrastructure
- **WebAssembly Community** - Signatures proposal and specification
