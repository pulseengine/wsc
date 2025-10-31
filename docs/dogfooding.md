# Dogfooding: Signing Our Own Releases

wasmsign2 releases use keyless signing to sign their own WASM artifacts.

## What Gets Signed

Every release includes:
- `wasmsign2-component.wasm` - Signed with keyless
- `wasmsign2-cli.wasm` - Signed with keyless
- OCI artifacts - Signed with Cosign

## Release Process

```yaml
# .github/workflows/release.yml
- Build WASM components
- Build native wasmsign2 CLI
- Sign with: wasmsign2 sign --keyless
- Publish to GitHub releases
- Sign OCI artifacts with Cosign
```

## Benefits

- **Validates** the implementation works in real CI/CD
- **Demonstrates** best practices to users
- **Tests** GitHub Actions OIDC integration continuously
- **Provides** transparency (all signatures in Rekor)

## Viewing Signatures

All wasmsign2 releases are logged in Rekor:

```bash
# Search for wasmsign2 signatures
rekor-cli search --email "github@pulseengine"

# View entry details
rekor-cli get --uuid <uuid>
```

## Security

**Before (traditional):**
- Manage long-lived signing keys
- Store keys in GitHub Secrets
- Manual key rotation

**After (keyless):**
- No keys to manage
- OIDC token from GitHub Actions
- Ephemeral keys (never stored)
- Logged in Rekor (tamper-evident)

## See Also

- [Keyless Signing Documentation](keyless.md)
- [Release Workflow](.github/workflows/release.yml)
