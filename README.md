# wsc - WebAssembly Signature Component

A tool and library for signing WebAssembly modules with enhanced Rekor verification and Bazel integration.

## About

**wsc** is an enhanced WebAssembly signing toolkit built on the foundation of [wasmsign2](https://github.com/wasm-signatures/wasmsign2) by Frank Denis. While maintaining compatibility with the WebAssembly modules signatures proposal, wsc adds production-oriented features:

- **Enhanced Rekor Verification**: Checkpoint-based verification with security hardening (key fingerprint validation, origin validation, cross-shard attack prevention)
- **Bazel Integration**: Full BUILD and MODULE.bazel support for hermetic builds
- **WIT Component Model**: Both library (`wsc-component.wasm`) and CLI (`wsc-cli.wasm`) builds
- **Keyless Signing**: Full Sigstore/Fulcio integration with OIDC authentication
- **CI/CD Pipeline**: Automated testing and release workflows

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

### Keyless Signing

wsc supports keyless signing using [Sigstore](https://www.sigstore.dev/):

```bash
wsc sign --keyless module.wasm
```

This will:
1. Authenticate via OIDC (GitHub, Google, Microsoft)
2. Generate an ephemeral key pair
3. Obtain a certificate from Fulcio
4. Sign the module
5. Upload signature to Rekor transparency log
6. Embed the certificate and Rekor bundle

### Inspecting a Module

```bash
wsc info module.wasm
```

### Creating a Key Pair

```bash
wsc generate -o keypair.txt
```

### Signing a WebAssembly Module

```bash
wsc sign -k keypair.txt module.wasm
```

### Verifying a WebAssembly Module

```bash
wsc verify -p public_key.txt module.wasm
```

### Verifying a WebAssembly Module Against Multiple Public Keys

```bash
wsc verify -p key1.txt -p key2.txt module.wasm
```

### Detaching a Signature from a Module

```bash
wsc detach -o signature.txt module.wasm
```

### Embedding a Detached Signature in a Module

```bash
wsc attach -s signature.txt module.wasm
```

### Partial Verification

wsc can verify signatures while ignoring specific custom sections:

```bash
wsc verify -p public_key.txt -i custom_section module.wasm
```

### OpenSSH Keys Support

wsc supports OpenSSH-formatted keys:

```bash
# Generate SSH key
ssh-keygen -t ed25519 -f key.pem

# Sign module
wsc sign -k key.pem module.wasm

# Verify module
wsc verify -p key.pem.pub module.wasm
```

### GitHub Integration

Fetch a user's SSH public keys from GitHub:

```bash
wsc verify -g github_username module.wasm
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
- [sigstore-rs Comparison](docs/sigstore_comparison.md) - Comparison with official Rust implementation

## Development Status

wsc is under active development. Core signing/verification and Rekor validation are functional. See [open issues](https://github.com/pulseengine/wsc/issues) for planned enhancements.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- **Frank Denis** - Original wasmsign2 implementation
- **Sigstore Project** - Keyless signing infrastructure
- **WebAssembly Community** - Signatures proposal and specification
