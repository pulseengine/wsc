# Immediate Security Fixes Required

## 🔴 CRITICAL: Fix Secret Key Debug Output (< 5 minutes)

**File**: `src/lib/src/signature/keys.rs:244-251`

**Current (INSECURE)**:
```rust
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SecretKey {{ [{}] }}",
            Hex::encode_to_string(self.sk.as_ref()).unwrap(),  // ← LEAKS KEY!
        )
    }
}
```

**Fix**:
```rust
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey {{ [REDACTED] }}")
    }
}
```

**Why**: Secret keys currently printed in:
- Debug output
- Panic messages
- Error traces
- Log files

---

## 🔴 HIGH: Add CI Security Checks (< 10 minutes)

**File**: `.github/workflows/rust.yml`

**Add before existing steps**:
```yaml
    - name: Install security tools
      run: |
        cargo install cargo-audit cargo-deny

    - name: Security Audit
      run: cargo audit

    - name: Dependency Policy Check
      run: cargo deny check

    - name: Clippy (strict)
      run: cargo clippy --all-targets --all-features -- -D warnings

    - name: Format Check
      run: cargo fmt --all -- --check
```

---

## 🟡 MEDIUM: Add Security Policy (< 30 minutes)

**File**: `SECURITY.md`

```markdown
# Security Policy

## Supported Contexts

### ✅ Supported (Production-Ready)
- Cloud/server deployments
- CI/CD pipelines with OIDC
- Internet-connected environments
- Software-based key management

### ❌ Not Supported (Requires Additional Work)
- Embedded systems
- Air-gapped environments
- Hardware security modules (HSM/TPM)
- Offline/no-internet deployments

## Reporting Vulnerabilities

Email: security@pulseengine.ai
PGP Key: [Add key here]

Please include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to respond within 48 hours.

## Known Limitations

1. **Secret keys in memory**: No zeroization after use
2. **No hardware security**: Software-only key storage
3. **Debug output**: May leak sensitive information in debug builds
4. **No revocation checking**: Fulcio certificate revocation not validated

## Security Disclosure Timeline

- Day 0: Report received
- Day 1-2: Initial response and triage
- Day 3-14: Fix development and testing
- Day 14: Public disclosure (or sooner for critical issues)
```

---

## 🟡 MEDIUM: Code Fixes for Key Zeroization (< 1 hour)

**File**: `src/lib/Cargo.toml`

**Add dependency**:
```toml
zeroize = { version = "1.8", features = ["derive"] }
```

**File**: `src/lib/src/signature/keys.rs`

**Update SecretKey**:
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Eq, PartialEq, Hash, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[zeroize(skip)]  // ed25519_compact handles its own zeroization
    pub sk: ed25519_compact::SecretKey,
}

// Remove Debug impl or make it redacting-only
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey {{ [REDACTED] }}")
    }
}
```

---

## Quick Command Reference

```bash
# Fix 1: Edit keys.rs manually (see above)

# Fix 2: Update CI workflow
# (Edit .github/workflows/rust.yml manually)

# Fix 3: Create SECURITY.md
# (Create file manually)

# Fix 4: Add zeroization
cargo add zeroize --features derive
# Then edit keys.rs (see above)

# Verify fixes
cargo test
cargo clippy -- -D warnings
cargo fmt --check

# Commit
git add -A
git commit -m "security: fix secret key exposure and add security tooling

- Redact secret keys in Debug output (CRITICAL)
- Add cargo-audit and cargo-deny to CI
- Add SECURITY.md with disclosure policy
- Implement key zeroization with zeroize crate
- Enable strict clippy checks
"
```

---

## Expected Impact

**Fix 1 (Debug output)**:
- Prevents: Key leakage in logs, panics, error messages
- Risk: CRITICAL
- Breaking: No (only changes debug output)

**Fix 2 (CI security)**:
- Prevents: Vulnerable dependencies, policy violations
- Risk: HIGH
- Breaking: May fail CI if issues found (good thing!)

**Fix 3 (SECURITY.md)**:
- Prevents: Unclear security expectations
- Risk: MEDIUM (documentation)
- Breaking: No

**Fix 4 (Zeroization)**:
- Prevents: Key material lingering in memory
- Risk: MEDIUM (depends on attack surface)
- Breaking: No (internal change)

---

## Testing After Fixes

```bash
# 1. Verify Debug output doesn't leak keys
cargo test -- --nocapture 2>&1 | grep -i "secret"
# Should see "[REDACTED]" not hex keys

# 2. Verify CI checks work
cargo audit
cargo deny check
cargo clippy -- -D warnings

# 3. Run full test suite
cargo test --workspace

# 4. Test in release mode
cargo test --release
```

---

## Timeline

| Fix | Priority | Time | When |
|-----|----------|------|------|
| Debug output redaction | CRITICAL | 5 min | NOW |
| CI security checks | HIGH | 10 min | TODAY |
| SECURITY.md | MEDIUM | 30 min | THIS WEEK |
| Key zeroization | MEDIUM | 1 hour | THIS WEEK |

**Total effort**: ~2 hours
**Total risk reduction**: HIGH
**Breaking changes**: None
