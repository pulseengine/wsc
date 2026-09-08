# Sigstore bundle fixtures (REQ-27 / #260)

Real, public bundles used to test `KeylessSignature::from_sigstore_bundle`.

- **`legacy_rekorbundle_keyless.json`** — the `SHA256SUMS.txt.cosign.bundle` from
  pulseengine/varve **v0.28.0** (public release). Legacy cosign `rekorBundle`
  shape: `{base64Signature, cert, rekorBundle:{SignedEntryTimestamp, Payload}}`,
  keyless (GitHub-OIDC Fulcio cert). Internally consistent: the hashedrekord
  body's `spec.data.hash.value` equals `sha256(SHA256SUMS.txt)` and
  `base64Signature` equals the body's signature content. This is the shape varve
  currently ships and the primary #260 target.

- **`protobuf_v0.3_localkey.json`** — a real cosign-emitted bundle,
  `mediaType: application/vnd.dev.sigstore.bundle.v0.3+json`, produced by
  `cosign sign-blob --new-bundle-format` with a local key (so it carries
  `verificationMaterial.publicKey`, not a Fulcio `certificate`). Used to test
  v0.3 envelope detection/parsing and the explicit rejection of non-keyless
  (public-key) bundles. A v0.3 *keyless* (cert) fixture needs Fulcio/OIDC and is
  covered by the gated e2e; see follow-up.
