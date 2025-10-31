# Keyless Signing

Keyless signing eliminates the need to manage long-lived cryptographic keys by using the [Sigstore](https://sigstore.dev) infrastructure.

## How It Works

```
1. Get OIDC identity token (from GitHub Actions, Google Cloud, etc.)
2. Generate ephemeral Ed25519 keypair (never stored)
3. Request short-lived certificate from Fulcio (~10 min validity)
4. Sign WASM module hash
5. Upload signature to Rekor transparency log
6. Embed signature in WASM module
```

## Usage

### GitHub Actions

```yaml
jobs:
  sign:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # Required for OIDC
    steps:
      - uses: actions/checkout@v4
      - run: wasmsign2 sign --keyless -i module.wasm -o signed.wasm
```

### Command Line

```bash
# Auto-detects OIDC provider from environment
wasmsign2 sign --keyless -i module.wasm -o signed.wasm
```

## Signature Format

Keyless signatures are embedded in a WASM custom section containing:

- **Ed25519 signature** (64 bytes)
- **X.509 certificate chain** (PEM format)
- **Rekor entry** (UUID, log index, inclusion proof)
- **Module hash** (SHA256)

Size overhead: ~2-3KB per signature

## Supported OIDC Providers

- **GitHub Actions** - Fully supported
- **Google Cloud** - Planned
- **GitLab CI** - Planned

## Security

**Benefits:**
- No long-lived private keys to manage or secure
- Signatures tied to CI/CD identity (repository + workflow)
- All signatures publicly logged in Rekor
- Automatic certificate expiration

**Trust Model:**
- Identity verified via OIDC provider (GitHub, Google, etc.)
- Certificate issued by Sigstore Fulcio CA
- Signature logged in Rekor transparency log
- Certificate validity: ~10 minutes (enforced by Fulcio)

## Verification (Coming Soon)

```bash
wasmsign2 verify --keyless \
  --identity-regexp "https://github.com/owner/repo" \
  --issuer "https://token.actions.githubusercontent.com" \
  -i signed.wasm
```

## References

- [Sigstore Documentation](https://docs.sigstore.dev/)
- [Fulcio Certificate Authority](https://docs.sigstore.dev/fulcio/overview)
- [Rekor Transparency Log](https://docs.sigstore.dev/rekor/overview)
