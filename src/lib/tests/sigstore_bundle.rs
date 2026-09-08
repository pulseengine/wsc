//! Integration tests for `KeylessSignature::from_sigstore_bundle` (REQ-27,
//! issue #260): ingesting an existing cosign / Sigstore bundle into a
//! `KeylessSignature` the offline verifiers accept.
//!
//! Fixtures are real bundles committed under
//! `tests/fixtures/sigstore_bundles/` and loaded with `include_str!`.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use wsc::WSError;
use wsc::container::SigstoreBundle;
use wsc::keyless::KeylessSignature;

const LEGACY_BUNDLE: &str =
    include_str!("fixtures/sigstore_bundles/legacy_rekorbundle_keyless.json");
const V03_LOCALKEY_BUNDLE: &str =
    include_str!("fixtures/sigstore_bundles/protobuf_v0.3_localkey.json");

/// The artifact SHA-256 recorded in the legacy fixture's hashedrekord body.
const LEGACY_MODULE_HASH_HEX: &str =
    "0f2e7d92ff7e1581d2a966db8dcdfc05054cdeb5395aec56561122e11b8a697f";

/// Test 1 — Legacy positive: the real legacy `rekorBundle` fixture ingests,
/// and every extracted field matches what the bundle actually carries.
#[test]
fn from_sigstore_bundle_legacy_positive() {
    let sig = KeylessSignature::from_sigstore_bundle(LEGACY_BUNDLE)
        .expect("legacy rekorBundle fixture must ingest");

    assert_eq!(
        sig.module_hash,
        hex::decode(LEGACY_MODULE_HASH_HEX).unwrap(),
        "module_hash must equal the hashedrekord body's data.hash.value"
    );

    assert!(!sig.cert_chain.is_empty(), "cert chain must be non-empty");
    assert!(
        sig.cert_chain[0].starts_with("-----BEGIN CERTIFICATE-----"),
        "leaf cert must be PEM text, got: {:?}",
        &sig.cert_chain[0][..sig.cert_chain[0].len().min(40)]
    );

    assert!(!sig.signature.is_empty(), "signature must be non-empty");

    assert_eq!(sig.rekor_entry.log_index, 2544945534);
    assert!(
        sig.rekor_entry.log_id.starts_with("c0d23d6a"),
        "log_id was: {}",
        sig.rekor_entry.log_id
    );
    assert!(
        !sig.rekor_entry.signed_entry_timestamp.is_empty(),
        "SET must be carried over"
    );
    // integrated_time is normalised to RFC3339 (Unix 1787295161).
    assert_eq!(sig.rekor_entry.integrated_time, "2026-08-21T06:52:41Z");
}

/// Test 1b — the strongest "the offline verifiers accept" proof that needs
/// neither network nor trust roots: `verify_rekor_body_binds_to_bundle`
/// decodes the ingested body and checks the artifact hash, signature bytes,
/// and leaf-cert DER all bind to the bundle. It must return `Ok`.
///
/// Non-vacuity: this is the positive partner of `..._negative_control` below.
/// If the digest, signature, or leaf cert were extracted inconsistently, this
/// call would return `Err`.
#[test]
fn from_sigstore_bundle_legacy_body_binding_accepts() {
    let sig =
        KeylessSignature::from_sigstore_bundle(LEGACY_BUNDLE).expect("legacy fixture must ingest");
    sig.verify_rekor_body_binds_to_bundle()
        .expect("ingested legacy bundle must pass offline Rekor-body binding");
}

/// Test 2 — Legacy negative control (faithful-extraction proof): flip one hex
/// char of the `hash.value` inside the base64 body, re-embed, re-ingest, and
/// assert the extracted `module_hash` DIFFERS from the untampered one. Proves
/// the digest is read faithfully from the body, not fabricated/hardcoded.
///
/// Non-vacuity: a SUT that hardcoded `module_hash` (e.g. `vec![0u8;32]`) or
/// recomputed it from a fixed source would yield the SAME value for both
/// inputs and this `assert_ne!` would fail.
#[test]
fn from_sigstore_bundle_legacy_negative_control_faithful_digest() {
    let genuine = KeylessSignature::from_sigstore_bundle(LEGACY_BUNDLE)
        .expect("genuine legacy fixture must ingest");

    // Decode the top-level bundle, reach into rekorBundle.Payload.body,
    // decode it, flip the first hex char of the artifact hash, re-encode.
    let mut bundle: serde_json::Value = serde_json::from_str(LEGACY_BUNDLE).unwrap();
    let body_b64 = bundle["rekorBundle"]["Payload"]["body"].as_str().unwrap();
    let body_bytes = BASE64.decode(body_b64).unwrap();
    let mut body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let orig = body["spec"]["data"]["hash"]["value"].as_str().unwrap();
    let mut chars: Vec<char> = orig.chars().collect();
    // Flip the first hex digit deterministically to a different hex digit.
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    let mutated: String = chars.into_iter().collect();
    assert_ne!(orig, mutated, "mutation must actually change the hash");
    body["spec"]["data"]["hash"]["value"] = serde_json::json!(mutated);

    let new_body_b64 = BASE64.encode(serde_json::to_vec(&body).unwrap());
    bundle["rekorBundle"]["Payload"]["body"] = serde_json::json!(new_body_b64);
    let tampered_json = serde_json::to_string(&bundle).unwrap();

    let tampered = KeylessSignature::from_sigstore_bundle(&tampered_json)
        .expect("tampered-but-well-formed bundle still ingests");

    assert_ne!(
        genuine.module_hash, tampered.module_hash,
        "corruption of the body hash must be propagated into module_hash"
    );
    assert_eq!(
        genuine.module_hash,
        hex::decode(LEGACY_MODULE_HASH_HEX).unwrap()
    );
}

/// Test 3 — v0.3 envelope + cert-requirement: the real
/// `protobuf_v0.3_localkey.json` bundle is detected as v0.3, its envelope is
/// parsed, and because it carries a raw public key (not a Fulcio cert) it is
/// rejected with the specific cert-requirement error.
///
/// Non-vacuity: the cert check runs BEFORE the messageSignature/digest
/// decode, so this error cannot be an incidental decode failure. If the SUT's
/// `publicKey` branch returned `Ok`/empty-chain, or was deleted so control
/// fell to the generic "no certificate in verificationMaterial" error, the
/// `contains("raw public key")` assertion below would fail — so the test
/// pins that the specific cert-requirement message fires.
#[test]
fn from_sigstore_bundle_v03_rejects_raw_public_key() {
    let err = KeylessSignature::from_sigstore_bundle(V03_LOCALKEY_BUNDLE)
        .expect_err("v0.3 local-key bundle must be rejected");

    match err {
        WSError::KeylessFormatError(msg) => {
            assert!(
                msg.contains("raw public key") && msg.contains("requires a certificate"),
                "expected the raw-public-key cert-requirement error, got: {msg}"
            );
        }
        other => panic!("expected KeylessFormatError, got: {other:?}"),
    }
}

/// Test 4 — Round-trip fidelity: ingest the legacy fixture, re-emit it as a
/// v0.3 `SigstoreBundle`, JSON round-trip it, and prove the signature,
/// module_hash, cert chain, and rekor fields all survive.
///
/// Intentionally-transformed fields are asserted in their re-emitted form and
/// documented inline; nothing is silently dropped.
#[test]
fn from_sigstore_bundle_legacy_round_trip_fidelity() {
    let sig =
        KeylessSignature::from_sigstore_bundle(LEGACY_BUNDLE).expect("legacy fixture must ingest");

    let bundle = SigstoreBundle::from_keyless_signature(&sig);
    let json = bundle.to_json().expect("bundle to_json");
    let bundle2 = SigstoreBundle::from_json(&json).expect("bundle from_json");

    // signature: preserved as base64 of the exact bytes.
    assert_eq!(
        BASE64.decode(&bundle2.message_signature.signature).unwrap(),
        sig.signature,
        "signature bytes must survive the round-trip"
    );

    // module_hash: emitted as lowercase hex by from_keyless_signature.
    assert_eq!(
        bundle2.message_signature.message_digest.digest,
        hex::encode(&sig.module_hash),
        "module_hash must survive as hex digest"
    );

    // cert chain: preserved as base64(DER). Re-derive the DER of the ingested
    // leaf PEM (strip headers, base64-decode) and compare byte-for-byte.
    let certs = &bundle2
        .verification_material
        .x509_certificate_chain
        .certificates;
    assert_eq!(
        certs.len(),
        sig.cert_chain.len(),
        "cert chain length must survive"
    );
    let leaf_der_from_bundle = BASE64.decode(&certs[0].raw_bytes).unwrap();
    let leaf_der_from_sig = pem_body_der(&sig.cert_chain[0]);
    assert_eq!(
        leaf_der_from_bundle, leaf_der_from_sig,
        "leaf certificate DER must survive"
    );

    // rekor fields.
    let tlog = &bundle2.verification_material.tlog_entries[0];
    assert_eq!(tlog.log_index, sig.rekor_entry.log_index.to_string());
    // LogId.key_id is a protobuf `bytes` field, so its JSON form is base64 —
    // what real cosign emits. RekorEntry::log_id holds the hex (Rekor REST)
    // form, so the emitter transcodes hex -> base64.
    assert_eq!(
        tlog.log_id.key_id,
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            hex::decode(&sig.rekor_entry.log_id).expect("fixture log_id is hex")
        ),
        "log id must be emitted as base64 of the key-id bytes"
    );
    assert_eq!(
        tlog.canonicalized_body.as_deref(),
        Some(sig.rekor_entry.body.as_str()),
        "canonicalized body (base64 rekord) must survive"
    );
    // The SET must be emitted at the spec location (inclusionPromise), not as
    // the non-conformant top-level field wsc <= 0.11.0 used.
    assert!(
        tlog.legacy_signed_entry_timestamp.is_none(),
        "must not emit the legacy top-level SET"
    );
    assert_eq!(
        tlog.inclusion_promise
            .as_ref()
            .map(|p| p.signed_entry_timestamp.as_str()),
        Some(sig.rekor_entry.signed_entry_timestamp.as_str()),
        "SET must survive at inclusionPromise.signedEntryTimestamp"
    );
    // integrated_time: KeylessSignature holds RFC3339; the bundle re-emits it
    // as Unix seconds — the same instant, matching the legacy fixture value.
    assert_eq!(
        tlog.integrated_time, "1787295161",
        "integrated_time must round-trip to the fixture's Unix seconds"
    );

    // Documented intentionally-dropped fields (offline verification does not
    // need them and the legacy bundle never carried them):
    //  - rekor_entry.uuid  (legacy omits it; stays empty)
    //  - rekor_entry.inclusion_proof (legacy carries only the SET)
    assert!(sig.rekor_entry.uuid.is_empty());
    assert!(sig.rekor_entry.inclusion_proof.is_empty());
}

/// Test 5 — Unrecognised shape: an object with neither `rekorBundle` nor a
/// v0.3 marker yields the specific unrecognised-format error.
#[test]
fn from_sigstore_bundle_unrecognized_format() {
    let err =
        KeylessSignature::from_sigstore_bundle("{}").expect_err("empty object must be rejected");
    match err {
        WSError::KeylessFormatError(msg) => {
            assert!(
                msg.contains("unrecognized Sigstore bundle format"),
                "got: {msg}"
            );
        }
        other => panic!("expected KeylessFormatError, got: {other:?}"),
    }
}

/// Strip PEM armor and decode the base64 body to DER bytes (test helper,
/// mirrors the crate's internal `pem_to_der`).
fn pem_body_der(pem: &str) -> Vec<u8> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----BEGIN") && !l.starts_with("-----END") && !l.is_empty())
        .collect();
    BASE64.decode(&b64).expect("valid base64 in PEM body")
}

/// The Rekor log ID recorded in the legacy fixture (`rekorBundle.Payload.logID`),
/// hex-encoded — 64 hex chars = the log's 32-byte key id.
const LEGACY_LOG_ID_HEX: &str = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d";

/// Pull a string field out of the legacy fixture so the v0.3 tests below are
/// built from the SAME real material the legacy fixture carries (real Fulcio
/// leaf, real ECDSA signature, real hashedrekord body, real SET) rather than
/// from synthetic bytes that could never fail a binding check.
fn legacy_field(path: &[&str]) -> String {
    let v: serde_json::Value = serde_json::from_str(LEGACY_BUNDLE).unwrap();
    let mut cur = &v;
    for p in path {
        cur = &cur[*p];
    }
    cur.as_str()
        .unwrap_or_else(|| panic!("legacy fixture field {path:?} must be a string"))
        .to_string()
}

/// The real Fulcio leaf certificate's DER bytes, recovered from the legacy
/// fixture's base64(PEM) `cert` field.
fn legacy_leaf_der() -> Vec<u8> {
    let pem = String::from_utf8(BASE64.decode(legacy_field(&["cert"])).unwrap()).unwrap();
    pem_body_der(&pem)
}

/// Test 7 — **Cross-format round trip through the v0.3 wire shape.**
///
/// Ingest the real legacy fixture, re-emit it as a v0.3 bundle with
/// `SigstoreBundle::from_keyless_signature`, then feed that JSON back through
/// `from_sigstore_bundle`. This is the only test that drives the v0.3
/// *cert-bearing* happy path (`verificationMaterial.x509CertificateChain` →
/// signature → digest → tlog mapping) end-to-end with real Fulcio material;
/// the committed v0.3 fixture is a local-key bundle that bails at the
/// cert-requirement check, so without this test the whole v0.3 mapping was
/// claimed but never executed.
///
/// Non-vacuity: the two offline oracles at the end
/// (`verify_rekor_body_binds_to_bundle`, `verify_cert_chain`) recompute the
/// digest/signature/leaf-DER binding and chain the leaf to the embedded Fulcio
/// roots at the extracted `integrated_time`. If the v0.3 path extracted any of
/// those four values inconsistently, they would return `Err`.
///
/// **This test documents two KNOWN DEFECTS it discovered** — see the inline
/// `KNOWN DEFECT` comments on `log_id` and `signed_entry_timestamp`. They are
/// characterized here, not fixed, because the fix belongs on the emitter
/// (`src/lib/src/container/bundle.rs`) and would change wsc's on-disk bundle
/// format. When either is fixed, the corresponding assertion below fails and
/// must be flipped to the equality it should always have had.
#[test]
fn from_sigstore_bundle_v03_cert_bearing_round_trip() {
    let sig_a =
        KeylessSignature::from_sigstore_bundle(LEGACY_BUNDLE).expect("legacy fixture must ingest");

    let json_bytes = SigstoreBundle::from_keyless_signature(&sig_a)
        .to_json()
        .expect("emit v0.3 bundle");
    let json = String::from_utf8(json_bytes).expect("emitted bundle is UTF-8");

    // Sanity: the emitted document really is the v0.3 wire shape, so the
    // re-ingest below exercises `from_v03_bundle` and not the legacy path.
    assert!(
        json.contains("application/vnd.dev.sigstore.bundle.v0.3+json")
            && json.contains("x509CertificateChain")
            && !json.contains("rekorBundle"),
        "emitted bundle must be the v0.3 shape"
    );

    let sig_b =
        KeylessSignature::from_sigstore_bundle(&json).expect("re-ingest of emitted v0.3 bundle");

    // --- fields that survive intact -------------------------------------
    assert_eq!(
        sig_b.signature, sig_a.signature,
        "signature bytes must survive the legacy -> v0.3 -> KeylessSignature round trip"
    );
    assert_eq!(
        sig_b.module_hash, sig_a.module_hash,
        "module_hash must survive (emitted as hex, re-read by decode_v03_digest's hex arm)"
    );
    assert_eq!(
        sig_b.module_hash,
        hex::decode(LEGACY_MODULE_HASH_HEX).unwrap(),
        "and it is still the fixture's real artifact digest"
    );

    // cert_chain: NOT string-equal, and legitimately so. The emit path does
    // PEM -> DER -> base64 and the ingest path does base64 -> DER -> PEM via
    // `der_to_pem`, which re-wraps at 64 columns and appends a trailing
    // newline. The certificate ITSELF must be byte-identical, so compare the
    // DER, which is the only representation that carries meaning.
    assert_eq!(
        sig_b.cert_chain.len(),
        sig_a.cert_chain.len(),
        "chain depth must survive"
    );
    assert_eq!(
        pem_body_der(&sig_b.cert_chain[0]),
        pem_body_der(&sig_a.cert_chain[0]),
        "leaf certificate DER must be byte-identical across the round trip"
    );
    assert_eq!(
        pem_body_der(&sig_b.cert_chain[0]),
        legacy_leaf_der(),
        "and it is still the fixture's real Fulcio leaf"
    );

    assert_eq!(
        sig_b.rekor_entry.log_index, sig_a.rekor_entry.log_index,
        "logIndex must survive (emitted as a decimal string, re-read by json_u64)"
    );
    assert_eq!(sig_b.rekor_entry.log_index, 2544945534);
    assert_eq!(
        sig_b.rekor_entry.body, sig_a.rekor_entry.body,
        "canonicalized hashedrekord body must survive verbatim"
    );
    assert_eq!(
        sig_b.rekor_entry.integrated_time, sig_a.rekor_entry.integrated_time,
        "integrated_time must survive (RFC3339 -> Unix seconds -> RFC3339)"
    );
    assert_eq!(sig_b.rekor_entry.integrated_time, "2026-08-21T06:52:41Z");

    // --- the two fields that used to be corrupted (now lossless) ---------
    //
    // Both were REAL emitter defects this round-trip test found, and both are
    // fixed in this PR (see container/bundle.rs). Ground truth came from a real
    // cosign `--new-bundle-format` bundle, which emits `logId.keyId` as base64
    // and puts the SET under `inclusionPromise` with no top-level field.

    // Was DEFECT #1: the emitter wrote `rekor.log_id` (hex) straight into
    // `LogId.key_id`, which the spec types as protobuf `bytes` (base64 in
    // JSON). A 64-char hex string is *also* valid base64, so the ingest
    // silently decoded it to 48 junk bytes — corrupting the Rekor log identity
    // with no diagnostic. The emitter now transcodes hex -> base64, so the log
    // id survives the round trip exactly.
    assert_eq!(
        sig_b.rekor_entry.log_id, sig_a.rekor_entry.log_id,
        "log id must survive the v0.3 round trip exactly"
    );
    assert_eq!(sig_b.rekor_entry.log_id, LEGACY_LOG_ID_HEX);

    // Was DEFECT #2: the emitter wrote the SET at the non-conformant top-level
    // `tlogEntries[0].signedEntryTimestamp`, while the ingest reads the spec
    // location `inclusionPromise.signedEntryTimestamp` — so the SET, the only
    // offline transparency proof a legacy bundle carries, was silently dropped
    // on wsc's own round trip. The emitter now writes the spec location.
    assert!(
        !sig_a.rekor_entry.signed_entry_timestamp.is_empty(),
        "the legacy fixture does carry a SET"
    );
    assert_eq!(
        sig_b.rekor_entry.signed_entry_timestamp, sig_a.rekor_entry.signed_entry_timestamp,
        "SET must survive the v0.3 round trip (was silently dropped before the fix)"
    );

    // Documented-empty by construction on BOTH sides (never silently skipped):
    //  - uuid: neither the legacy shape nor the v0.3 shape carries an entry
    //    UUID, so both are empty. See format.rs:238-246 / :375.
    //  - inclusion_proof: the legacy bundle carries only a SET, so there is
    //    nothing to emit and nothing to re-read.
    assert_eq!(sig_a.rekor_entry.uuid, "");
    assert_eq!(sig_b.rekor_entry.uuid, "");
    assert!(sig_a.rekor_entry.inclusion_proof.is_empty());
    assert!(sig_b.rekor_entry.inclusion_proof.is_empty());

    // --- offline oracles on the RE-INGESTED signature ---------------------
    // These are what make the field assertions above non-vacuous: they
    // recompute the relationships between the extracted values.
    sig_b
        .verify_rekor_body_binds_to_bundle()
        .expect("v0.3 re-ingested bundle must still pass offline Rekor-body binding");
    sig_b
        .verify_cert_chain()
        .expect("v0.3 re-ingested leaf must still chain to embedded Fulcio roots");
}

/// Test 8 — **Spec-shaped v0.3 keyless bundle (what real cosign emits).**
///
/// Test 7 goes through wsc's own emitter, which uses the plural
/// `x509CertificateChain` container, hex digests, and a top-level SET. Real
/// cosign `--new-bundle-format` keyless bundles instead use the singular
/// `verificationMaterial.certificate.rawBytes`, a base64 digest, a base64
/// `logId.keyId`, and the SET under `inclusionPromise` — a completely
/// different set of branches that no fixture reaches.
///
/// This test hand-builds that shape from the SAME real material the legacy
/// fixture carries (real Fulcio leaf DER, real signature, real hashedrekord
/// body, real SET, real log id) and asserts every field comes back exactly.
///
/// It is also the control for the two KNOWN DEFECTS pinned in test 7: here
/// `log_id` and `signed_entry_timestamp` DO come back intact, which proves the
/// ingest side is spec-correct and locates both defects on the emitter.
#[test]
fn from_sigstore_bundle_v03_spec_shaped_keyless_positive() {
    let leaf_der = legacy_leaf_der();
    let sig_b64 = legacy_field(&["base64Signature"]);
    let body_b64 = legacy_field(&["rekorBundle", "Payload", "body"]);
    let set_b64 = legacy_field(&["rekorBundle", "SignedEntryTimestamp"]);

    let bundle = serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            // Singular `certificate`, as real cosign keyless bundles use.
            "certificate": { "rawBytes": BASE64.encode(&leaf_der) },
            "tlogEntries": [{
                // v0.3 encodes int64 as a decimal STRING.
                "logIndex": "2544945534",
                // Spec form: base64 of the log's raw key-id bytes.
                "logId": { "keyId": BASE64.encode(hex::decode(LEGACY_LOG_ID_HEX).unwrap()) },
                "canonicalizedBody": body_b64,
                "integratedTime": "1787295161",
                // Spec form: SET nested under inclusionPromise.
                "inclusionPromise": { "signedEntryTimestamp": set_b64 },
            }],
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                // Spec form: base64 digest (44 chars) — exercises the base64
                // arm of `decode_v03_digest`, which test 7's hex form does not.
                "digest": BASE64.encode(hex::decode(LEGACY_MODULE_HASH_HEX).unwrap()),
            },
            "signature": sig_b64,
        },
    });

    let sig = KeylessSignature::from_sigstore_bundle(&bundle.to_string())
        .expect("spec-shaped v0.3 keyless bundle must ingest");

    assert_eq!(
        sig.cert_chain.len(),
        1,
        "the singular `certificate` yields a one-entry chain"
    );
    assert_eq!(
        pem_body_der(&sig.cert_chain[0]),
        leaf_der,
        "leaf DER must round-trip through der_to_pem byte-for-byte"
    );
    assert_eq!(
        sig.signature,
        BASE64.decode(&sig_b64).unwrap(),
        "signature bytes must come from messageSignature.signature"
    );
    assert_eq!(
        sig.module_hash,
        hex::decode(LEGACY_MODULE_HASH_HEX).unwrap(),
        "base64 digest must decode to the fixture's artifact hash"
    );
    assert_eq!(sig.rekor_entry.log_index, 2544945534);
    assert_eq!(
        sig.rekor_entry.log_id, LEGACY_LOG_ID_HEX,
        "base64 keyId must be re-encoded to the real hex log id (control for DEFECT #1)"
    );
    assert_eq!(
        sig.rekor_entry.signed_entry_timestamp, set_b64,
        "SET under inclusionPromise must be carried over (control for DEFECT #2)"
    );
    assert_eq!(sig.rekor_entry.body, body_b64);
    assert_eq!(sig.rekor_entry.integrated_time, "2026-08-21T06:52:41Z");

    // Offline oracles: the extracted digest / signature / leaf-DER must be
    // mutually consistent, and the leaf must chain to the embedded Fulcio
    // roots at the extracted integrated_time.
    sig.verify_rekor_body_binds_to_bundle()
        .expect("spec-shaped v0.3 bundle must pass offline Rekor-body binding");
    sig.verify_cert_chain()
        .expect("spec-shaped v0.3 leaf must chain to embedded Fulcio roots");
}

/// Test 9 — v0.3 negative control (faithful extraction, mirroring test 2 for
/// the v0.3 path): flip one byte of the base64 `messageDigest.digest` and
/// assert the extracted `module_hash` changes. Proves the v0.3 digest is read
/// from the bundle, not recomputed or hardcoded.
#[test]
fn from_sigstore_bundle_v03_negative_control_faithful_digest() {
    let leaf_der = legacy_leaf_der();
    let mut digest = hex::decode(LEGACY_MODULE_HASH_HEX).unwrap();
    digest[0] ^= 0xff;

    let bundle = serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": { "rawBytes": BASE64.encode(&leaf_der) },
            "tlogEntries": [{
                "logIndex": "2544945534",
                "logId": { "keyId": BASE64.encode(hex::decode(LEGACY_LOG_ID_HEX).unwrap()) },
                "integratedTime": "1787295161",
            }],
        },
        "messageSignature": {
            "messageDigest": { "algorithm": "SHA2_256", "digest": BASE64.encode(&digest) },
            "signature": legacy_field(&["base64Signature"]),
        },
    });

    let sig = KeylessSignature::from_sigstore_bundle(&bundle.to_string())
        .expect("well-formed bundle with a corrupted digest still ingests");
    assert_eq!(
        sig.module_hash, digest,
        "the corrupted digest must be propagated verbatim, never 'fixed'"
    );
    assert_ne!(
        sig.module_hash,
        hex::decode(LEGACY_MODULE_HASH_HEX).unwrap()
    );

    // The absent `canonicalizedBody` / `inclusionPromise` are read as empty
    // (format.rs:365-372 `unwrap_or_default`) rather than erroring — asserted
    // rather than left unexamined, because a silently-empty transparency proof
    // is exactly what a verifier must not accept unnoticed.
    assert_eq!(sig.rekor_entry.body, "");
    assert_eq!(sig.rekor_entry.signed_entry_timestamp, "");
}

/// Test 6 — `verify_cert_chain` (offline: embedded Fulcio trust roots, no
/// network) accepts the ingested legacy bundle. This is the leg that depends
/// on `integrated_time` being RFC3339: `verify_cert_chain` parses that field
/// with `parse_from_rfc3339` and checks the leaf cert's validity window
/// against it. The fixture cert's window is 2026-08-21T06:52:40Z ..
/// 07:02:40Z and integrated_time is 06:52:41Z (inside the window), so this
/// returns `Ok`. A bare Unix-seconds string here would make the parse fail
/// and this test would catch the regression.
#[test]
fn from_sigstore_bundle_legacy_verify_cert_chain_accepts() {
    let sig =
        KeylessSignature::from_sigstore_bundle(LEGACY_BUNDLE).expect("legacy fixture must ingest");
    sig.verify_cert_chain()
        .expect("ingested legacy leaf cert must chain to embedded Fulcio roots at integrated_time");
}
