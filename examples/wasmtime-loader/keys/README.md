# Trusted Keys Directory

Place trusted public keys in this directory.

## Generate a Key Pair

```bash
# Generate signing key (keep this secret!)
cargo run --bin wsc -- generate-key -o signing-key

# Extract public key for verification (safe to distribute)
cargo run --bin wsc -- export-public-key -k signing-key -o trusted.pub
```

## Key Management

**Private key (`signing-key`):**
- Keep secure and secret
- Use for signing components
- Store in a secure location (HSM, key vault, etc.)
- Never commit to version control

**Public key (`trusted.pub`):**
- Safe to distribute
- Include in your loader/runtime
- Can be committed to version control
- Used only for verification

## Multiple Keys

You can trust multiple public keys:

```bash
trusted-key-1.pub  # Signer: Alice
trusted-key-2.pub  # Signer: Bob
trusted-key-3.pub  # Signer: CI system
```

The loader will accept components signed by ANY of these keys.

## Key Rotation

To rotate keys:

1. Generate new key pair
2. Add new public key to trusted set
3. Re-sign components with new key
4. After transition period, remove old public key
