use wsc::{BoxedPredicate, KeyPair, Module, PublicKey, PublicKeySet, SecretKey, Section, WSError};
use wsc::airgapped::{
    CertificateAuthority, SignedTrustBundle, TransparencyLog, TrustBundle,
    TRUST_BUNDLE_FORMAT_VERSION,
    fetch_sigstore_trusted_root, trusted_root_to_bundle, SIGSTORE_TRUSTED_ROOT_URL,
};
use wsc::audit::{self, AuditConfig, LogDestination};
use wsc::composition::{
    extract_transformation_attestation, extract_all_transformation_attestations,
    extract_transformation_audit_trail, embed_transformation_attestation,
    TransformationAttestation, TransformationAttestationBuilder, TransformationType,
    ChainVerificationPolicy, ChainVerificationMode, TrustedToolInfo, TrustedPublicKey,
    verify_transformation_chain,
};
use wsc::policy::{Policy, Enforcement, evaluate_policy};

use wsc::reexports::log;

use clap::{Arg, ArgAction, Command, crate_description, crate_name, crate_version};
use regex::RegexBuilder;
use std::fs::File;
use std::io::{BufReader, prelude::*};
use std::path::Path;

/// Helper function to create a file with parent directories
fn create_file_with_dirs(path: impl AsRef<Path>) -> Result<File, WSError> {
    let path = path.as_ref();
    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            WSError::InternalError(format!(
                "Failed to create parent directory for '{}': {}",
                path.display(),
                e
            ))
        })?;
    }
    File::create(path).map_err(|e| {
        WSError::InternalError(format!("Failed to create file '{}': {}", path.display(), e))
    })
}

/// Helper function to open a file with better error messages
fn open_file(path: impl AsRef<Path>) -> Result<File, WSError> {
    let path = path.as_ref();
    File::open(path).map_err(|e| {
        WSError::InternalError(format!("Failed to open file '{}': {}", path.display(), e))
    })
}

fn start() -> Result<(), WSError> {
    let matches = Command::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .arg(
            Arg::new("verbose")
                .short('v')
                .action(ArgAction::SetTrue)
                .help("Verbose output"),
        )
        .arg(
            Arg::new("debug")
                .short('d')
                .action(ArgAction::SetTrue)
                .help("Prints debugging information"),
        )
        .arg(
            Arg::new("audit")
                .long("audit")
                .action(ArgAction::SetTrue)
                .help("Enable structured audit logging (JSON to stderr)"),
        )
        .arg(
            Arg::new("audit-file")
                .long("audit-file")
                .value_name("FILE")
                .help("Write audit logs to FILE instead of stderr"),
        )
        .subcommand(
            Command::new("keygen")
                .about("Generate a new key pair")
                .arg(
                    Arg::new("secret_key")
                        .value_name("secret_key_file")
                        .long("secret-key")
                        .short('k')
                        .required(true)
                        .help("Secret key file"),
                )
                .arg(
                    Arg::new("public_key")
                        .value_name("public_key_file")
                        .long("public-key")
                        .short('K')
                        .required(true)
                        .help("Public key file"),
                ),
        )
        .subcommand(
            Command::new("show")
                .about("Print the structure of a module")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input file"),
                ),
        )
        .subcommand(
            Command::new("split")
                .about("Add cutting points to a module to enable partial verification")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::new("out")
                        .value_name("output_file")
                        .long("output-file")
                        .short('o')
                        .required(true)
                        .help("Output file"),
                )
                .arg(
                    Arg::new("splits")
                        .long("split")
                        .short('s')
                        .value_name("regex")
                        .help("Custom section names to be signed"),
                ),
        )
        .subcommand(
            Command::new("sign")
                .about("Sign a module")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::new("out")
                        .value_name("output_file")
                        .long("output-file")
                        .short('o')
                        .required(true)
                        .help("Output file"),
                )
                .arg(
                    Arg::new("keyless")
                        .long("keyless")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("secret_key")
                        .help("Use keyless signing (ephemeral keys + Fulcio + Rekor)"),
                )
                .arg(
                    Arg::new("secret_key")
                        .value_name("secret_key_file")
                        .long("secret-key")
                        .short('k')
                        .required_unless_present("keyless")
                        .help("Secret key file"),
                )
                .arg(
                    Arg::new("public_key")
                        .value_name("public_key_file")
                        .long("public-key")
                        .short('K')
                        .help("Public key file (PEM or DER format)"),
                )
                .arg(
                    Arg::new("signature_file")
                        .value_name("signature_file")
                        .long("signature-file")
                        .short('S')
                        .help("Signature file"),
                ),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a module's signature")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::new("keyless")
                        .long("keyless")
                        .action(ArgAction::SetTrue)
                        .conflicts_with_all(["public_key", "signature_file", "splits"])
                        .help("Verify keyless signature (Sigstore/Fulcio/Rekor)"),
                )
                .arg(
                    Arg::new("cert_identity")
                        .value_name("identity")
                        .long("cert-identity")
                        .requires("keyless")
                        .help("Expected identity in the certificate (e.g., user@example.com)"),
                )
                .arg(
                    Arg::new("cert_oidc_issuer")
                        .value_name("issuer")
                        .long("cert-oidc-issuer")
                        .requires("keyless")
                        .help("Expected OIDC issuer (e.g., https://token.actions.githubusercontent.com)"),
                )
                .arg(
                    Arg::new("public_key")
                        .value_name("public_key_file")
                        .long("public-key")
                        .short('K')
                        .required(false)
                        .help("Public key file (PEM or DER format)"),
                )
                .arg(
                    Arg::new("signature_file")
                        .value_name("signature_file")
                        .long("signature-file")
                        .short('S')
                        .help("Signature file"),
                )
                .arg(
                    Arg::new("splits")
                        .long("split")
                        .short('s')
                        .value_name("regex")
                        .help("Custom section names to be verified"),
                ),
        )
        .subcommand(
            Command::new("detach")
                .about("Detach the signature from a module")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::new("out")
                        .value_name("output_file")
                        .long("output-file")
                        .short('o')
                        .required(true)
                        .help("Output file"),
                )
                .arg(
                    Arg::new("signature_file")
                        .value_name("signature_file")
                        .long("signature-file")
                        .short('S')
                        .required(true)
                        .help("Signature file"),
                ),
        )
        .subcommand(
            Command::new("attach")
                .about("Embed a detach signature into a module")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::new("out")
                        .value_name("output_file")
                        .long("output-file")
                        .short('o')
                        .required(true)
                        .help("Output file"),
                )
                .arg(
                    Arg::new("signature_file")
                        .value_name("signature_file")
                        .long("signature-file")
                        .short('S')
                        .required(true)
                        .help("Signature file"),
                ),
        )
        .subcommand(
            Command::new("verify_matrix")
                .about("Batch verification against multiple public keys")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input file"),
                )
                .arg(
                    Arg::new("public_keys")
                        .value_name("public_key_files")
                        .long("public-keys")
                        .short('K')
                        .num_args(1..)
                        .required(false)
                        .help("Public key files (PEM or DER format)"),
                )
                .arg(
                    Arg::new("splits")
                        .long("split")
                        .short('s')
                        .value_name("regex")
                        .help("Custom section names to be verified"),
                ),
        )
        .subcommand(
            Command::new("bundle")
                .about("Manage trust bundles for air-gapped verification")
                .subcommand(
                    Command::new("create")
                        .about("Create a new trust bundle")
                        .arg(
                            Arg::new("out")
                                .value_name("output_file")
                                .long("output-file")
                                .short('o')
                                .required(true)
                                .help("Output bundle file (JSON)"),
                        )
                        .arg(
                            Arg::new("version")
                                .value_name("version")
                                .long("version")
                                .short('V')
                                .default_value("1")
                                .help("Bundle version (monotonic for anti-rollback)"),
                        )
                        .arg(
                            Arg::new("validity_days")
                                .value_name("days")
                                .long("validity-days")
                                .default_value("365")
                                .help("Bundle validity period in days"),
                        )
                        .arg(
                            Arg::new("ca_cert")
                                .value_name("pem_file")
                                .long("ca-cert")
                                .num_args(1..)
                                .help("Certificate authority PEM files (Fulcio roots)"),
                        )
                        .arg(
                            Arg::new("rekor_key")
                                .value_name("pem_file")
                                .long("rekor-key")
                                .help("Rekor transparency log public key (PEM)"),
                        ),
                )
                .subcommand(
                    Command::new("sign")
                        .about("Sign a trust bundle with Ed25519 key")
                        .arg(
                            Arg::new("in")
                                .value_name("input_file")
                                .long("input-file")
                                .short('i')
                                .required(true)
                                .help("Input bundle file (JSON)"),
                        )
                        .arg(
                            Arg::new("out")
                                .value_name("output_file")
                                .long("output-file")
                                .short('o')
                                .required(true)
                                .help("Output signed bundle file (JSON)"),
                        )
                        .arg(
                            Arg::new("secret_key")
                                .value_name("secret_key_file")
                                .long("secret-key")
                                .short('k')
                                .required(true)
                                .help("Ed25519 secret key file"),
                        ),
                )
                .subcommand(
                    Command::new("verify")
                        .about("Verify a signed trust bundle")
                        .arg(
                            Arg::new("in")
                                .value_name("input_file")
                                .long("input-file")
                                .short('i')
                                .required(true)
                                .help("Input signed bundle file (JSON)"),
                        )
                        .arg(
                            Arg::new("public_key")
                                .value_name("public_key_file")
                                .long("public-key")
                                .short('K')
                                .required(true)
                                .help("Ed25519 public key file"),
                        ),
                )
                .subcommand(
                    Command::new("inspect")
                        .about("Display trust bundle contents")
                        .arg(
                            Arg::new("in")
                                .value_name("input_file")
                                .long("input-file")
                                .short('i')
                                .required(true)
                                .help("Input bundle file (JSON, signed or unsigned)"),
                        ),
                )
                .subcommand(
                    Command::new("fetch")
                        .about("Fetch trust material from Sigstore TUF repository")
                        .arg(
                            Arg::new("out")
                                .value_name("output_file")
                                .long("output-file")
                                .short('o')
                                .required(true)
                                .help("Output bundle file (JSON)"),
                        )
                        .arg(
                            Arg::new("version")
                                .value_name("version")
                                .long("version")
                                .short('V')
                                .default_value("1")
                                .help("Bundle version (monotonic for anti-rollback)"),
                        )
                        .arg(
                            Arg::new("validity_days")
                                .value_name("days")
                                .long("validity-days")
                                .default_value("90")
                                .help("Bundle validity period in days"),
                        )
                        .arg(
                            Arg::new("sign")
                                .long("sign")
                                .value_name("secret_key_file")
                                .help("Sign the bundle with this Ed25519 key"),
                        ),
                ),
        )
        .subcommand(
            Command::new("show-chain")
                .about("Display transformation chain from a module")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input WASM file"),
                )
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Output as JSON"),
                ),
        )
        .subcommand(
            Command::new("verify-chain")
                .about("Verify transformation attestation chain")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input WASM file"),
                )
                .arg(
                    Arg::new("policy")
                        .long("policy")
                        .short('p')
                        .value_name("FILE")
                        .help("TOML policy file for SLSA-aware verification"),
                )
                .arg(
                    Arg::new("trusted_tools")
                        .long("trusted-tools")
                        .value_name("FILE")
                        .help("JSON file with trusted tools configuration (legacy)"),
                )
                .arg(
                    Arg::new("require_signatures")
                        .long("require-signatures")
                        .action(ArgAction::SetTrue)
                        .help("Require all root inputs to be signed"),
                )
                .arg(
                    Arg::new("max_age")
                        .long("max-age-days")
                        .value_name("DAYS")
                        .help("Maximum age of attestations in days"),
                )
                .arg(
                    Arg::new("require_attestation_signatures")
                        .long("require-attestation-signatures")
                        .action(ArgAction::SetTrue)
                        .help("Require attestations to be signed and verify against trusted public keys"),
                )
                .arg(
                    Arg::new("strict")
                        .long("strict")
                        .action(ArgAction::SetTrue)
                        .help("Override all policy rules to strict enforcement"),
                )
                .arg(
                    Arg::new("report_only")
                        .long("report-only")
                        .action(ArgAction::SetTrue)
                        .help("Override all policy rules to report-only mode (no failures)"),
                ),
        )
        .subcommand(
            Command::new("attest")
                .about("Record a transformation attestation")
                .arg(
                    Arg::new("in")
                        .value_name("input_file")
                        .long("input-file")
                        .short('i')
                        .required(true)
                        .help("Input WASM file (before transformation)"),
                )
                .arg(
                    Arg::new("out")
                        .value_name("output_file")
                        .long("output-file")
                        .short('o')
                        .required(true)
                        .help("Output WASM file (after transformation, attestation will be embedded)"),
                )
                .arg(
                    Arg::new("tool_name")
                        .long("tool-name")
                        .value_name("NAME")
                        .required(true)
                        .help("Name of the transformation tool"),
                )
                .arg(
                    Arg::new("tool_version")
                        .long("tool-version")
                        .value_name("VERSION")
                        .required(true)
                        .help("Version of the transformation tool"),
                )
                .arg(
                    Arg::new("type")
                        .long("type")
                        .value_name("TYPE")
                        .value_parser(["optimization", "composition", "instrumentation", "stripping", "custom"])
                        .default_value("custom")
                        .help("Type of transformation"),
                ),
        )
        .get_matches();

    let verbose = matches.get_flag("verbose");
    let debug = matches.get_flag("debug");
    let audit_enabled = matches.get_flag("audit");
    let audit_file = matches.get_one::<String>("audit-file").map(|s| s.as_str());

    env_logger::builder()
        .format_timestamp(None)
        .format_level(false)
        .format_module_path(false)
        .format_target(false)
        .filter_level(if debug {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .init();

    // Initialize audit logging if enabled
    if audit_enabled || audit_file.is_some() {
        let destination = match audit_file {
            Some(path) => LogDestination::File(path.to_string()),
            None => LogDestination::Stderr,
        };
        audit::init(AuditConfig {
            enabled: true,
            destination,
            json_format: true,
            redact_pii: true,
            filter: "wsc::audit=info".to_string(),
        });
    }

    if let Some(matches) = matches.subcommand_matches("show") {
        let input_file = matches.get_one::<String>("in").map(|s| s.as_str());
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?;
        let module = Module::deserialize_from_file(input_file)?;
        module.show(verbose)?;
    } else if let Some(matches) = matches.subcommand_matches("keygen") {
        let kp = KeyPair::generate();
        let sk_file = matches
            .get_one::<String>("secret_key")
            .map(|s| s.as_str())
            .ok_or(WSError::UsageError("Missing secret key file"))?;
        let pk_file = matches
            .get_one::<String>("public_key")
            .map(|s| s.as_str())
            .ok_or(WSError::UsageError("Missing public key file"))?;
        kp.sk.to_file(sk_file)?;
        println!("Secret key saved to [{sk_file}]");
        kp.pk.to_file(pk_file)?;
        println!("Public key saved to [{pk_file}]");
    } else if let Some(matches) = matches.subcommand_matches("split") {
        let input_file = matches.get_one::<String>("in").map(|s| s.as_str());
        let output_file = matches.get_one::<String>("out").map(|s| s.as_str());
        let splits = matches.get_one::<String>("splits").map(|s| s.as_str());
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?;
        let output_file = output_file.ok_or(WSError::UsageError("Missing output file"))?;
        let signed_sections_rx = match splits {
            None => None,
            Some(splits) => Some(
                RegexBuilder::new(splits)
                    .case_insensitive(false)
                    .multi_line(false)
                    .dot_matches_new_line(false)
                    .size_limit(1_000_000)
                    .dfa_size_limit(1_000_000)
                    .nest_limit(1000)
                    .build()
                    .map_err(|_| WSError::InvalidArgument)?,
            ),
        };
        let mut module = Module::deserialize_from_file(input_file)?;
        module = module.split(|section| match section {
            Section::Standard(_) => true,
            Section::Custom(custom_section) => {
                if let Some(signed_sections_rx) = &signed_sections_rx {
                    signed_sections_rx.is_match(custom_section.name())
                } else {
                    true
                }
            }
        })?;
        module.serialize_to_file(output_file)?;
        println!("* Split module structure:\n");
        module.show(verbose)?;
    } else if let Some(matches) = matches.subcommand_matches("sign") {
        let input_file = matches.get_one::<String>("in").map(|s| s.as_str());
        let output_file = matches.get_one::<String>("out").map(|s| s.as_str());
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?;
        let output_file = output_file.ok_or(WSError::UsageError("Missing output file"))?;

        if matches.get_flag("keyless") {
            // Keyless signing path
            use wsc::keyless::{KeylessConfig, KeylessSigner};

            println!("Using keyless signing...");
            let config = KeylessConfig::default();
            let signer = KeylessSigner::with_config(config)?;

            let module = Module::deserialize_from_file(input_file)?;
            let (signed_module, keyless_sig) = signer.sign_module(module)?;

            signed_module.serialize_to_file(output_file)?;

            println!("\n✓ Module signed with keyless signature");
            println!("  Identity: {}", keyless_sig.get_identity()?);
            println!("  Issuer: {}", keyless_sig.get_issuer()?);
            if !keyless_sig.rekor_entry.uuid.is_empty() {
                println!("  Rekor entry: {}", keyless_sig.rekor_entry.uuid);
                println!("  Rekor index: {}", keyless_sig.rekor_entry.log_index);
            }
            println!("\n* Signed module structure:\n");
            signed_module.show(verbose)?;
        } else {
            // Traditional key-based signing
            let signature_file = matches
                .get_one::<String>("signature_file")
                .map(|s| s.as_str());
            let sk_file = matches
                .get_one::<String>("secret_key")
                .map(|s| s.as_str())
                .ok_or(WSError::UsageError("Missing secret key file"))?;
            let sk = SecretKey::from_file(sk_file)?;
            let pk_file = matches.get_one::<String>("public_key").map(|s| s.as_str());
            let key_id = if let Some(pk_file) = pk_file {
                let pk = PublicKey::from_file(pk_file)?.attach_default_key_id();
                pk.key_id().cloned()
            } else {
                None
            };
            let module = Module::deserialize_from_file(input_file)?;
            let (module, signature) =
                sk.sign_multi(module, key_id.as_ref(), signature_file.is_some(), false)?;
            if let Some(signature_file) = signature_file {
                module.serialize_to_file(output_file)?;
                create_file_with_dirs(signature_file)?.write_all(&signature)?;
            } else {
                module.serialize_to_file(output_file)?;
            }
            println!("* Signed module structure:\n");
            module.show(verbose)?;
        }
    } else if let Some(matches) = matches.subcommand_matches("verify") {
        let input_file = matches.get_one::<String>("in").map(|s| s.as_str());
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?;

        if matches.get_flag("keyless") {
            // Keyless verification path
            use wsc::keyless::KeylessVerifier;

            let cert_identity = matches.get_one::<String>("cert_identity").map(|s| s.as_str());
            let cert_oidc_issuer = matches.get_one::<String>("cert_oidc_issuer").map(|s| s.as_str());

            println!("Verifying keyless signature...");
            let module = Module::deserialize_from_file(input_file)?;
            let result = KeylessVerifier::verify(&module, cert_identity, cert_oidc_issuer)?;

            println!("\n✓ Keyless signature is valid");
            println!("  Identity: {}", result.identity);
            println!("  Issuer: {}", result.issuer);
            if !result.rekor_uuid.is_empty() && result.rekor_uuid != "skipped" {
                println!("  Rekor entry: {}", result.rekor_uuid);
                println!("  Rekor index: {}", result.rekor_log_index);
            }
        } else {
            // Traditional key-based verification
            let signature_file = matches
                .get_one::<String>("signature_file")
                .map(|s| s.as_str());
            let splits = matches.get_one::<String>("splits").map(|s| s.as_str());
            let signed_sections_rx = match splits {
                None => None,
                Some(splits) => Some(
                    RegexBuilder::new(splits)
                        .case_insensitive(false)
                        .multi_line(false)
                        .dot_matches_new_line(false)
                        .size_limit(1_000_000)
                        .dfa_size_limit(1_000_000)
                        .nest_limit(1000)
                        .build()
                        .map_err(|_| WSError::InvalidArgument)?,
                ),
            };
            let pk_file = matches
                .get_one::<String>("public_key")
                .map(|s| s.as_str())
                .ok_or(WSError::UsageError("Missing public key file"))?;
            let pk = PublicKey::from_file(pk_file)?.attach_default_key_id();
            let mut detached_signatures_ = vec![];
            let detached_signatures = match signature_file {
                None => None,
                Some(signature_file) => {
                    open_file(signature_file)?.read_to_end(&mut detached_signatures_)?;
                    Some(detached_signatures_.as_slice())
                }
            };
            let mut reader = BufReader::new(open_file(input_file)?);
            if let Some(signed_sections_rx) = &signed_sections_rx {
                pk.verify_multi(&mut reader, detached_signatures, |section| match section {
                    Section::Standard(_) => true,
                    Section::Custom(custom_section) => {
                        signed_sections_rx.is_match(custom_section.name())
                    }
                })?;
            } else {
                pk.verify(&mut reader, detached_signatures)?;
            }
            println!("Signature is valid.");
        }
    } else if let Some(matches) = matches.subcommand_matches("detach") {
        let input_file = matches.get_one::<String>("in").map(|s| s.as_str());
        let output_file = matches.get_one::<String>("out").map(|s| s.as_str());
        let signature_file = matches
            .get_one::<String>("signature_file")
            .map(|s| s.as_str());
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?;
        let output_file = output_file.ok_or(WSError::UsageError("Missing output file"))?;
        let signature_file =
            signature_file.ok_or(WSError::UsageError("Missing detached signature file"))?;
        let module = Module::deserialize_from_file(input_file)?;
        let (module, detached_signature) = module.detach_signature()?;
        create_file_with_dirs(signature_file)?.write_all(&detached_signature)?;
        module.serialize_to_file(output_file)?;
        println!("Signature is now detached.");
    } else if let Some(matches) = matches.subcommand_matches("attach") {
        let input_file = matches.get_one::<String>("in").map(|s| s.as_str());
        let output_file = matches.get_one::<String>("out").map(|s| s.as_str());
        let signature_file = matches
            .get_one::<String>("signature_file")
            .map(|s| s.as_str());
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?;
        let output_file = output_file.ok_or(WSError::UsageError("Missing output file"))?;
        let signature_file =
            signature_file.ok_or(WSError::UsageError("Missing detached signature file"))?;
        let mut detached_signature = vec![];
        open_file(signature_file)?.read_to_end(&mut detached_signature)?;
        let mut module = Module::deserialize_from_file(input_file)?;
        module = module.attach_signature(&detached_signature)?;
        module.serialize_to_file(output_file)?;
        println!("Signature is now embedded as a custom section.");
    } else if let Some(matches) = matches.subcommand_matches("verify_matrix") {
        let input_file = matches.get_one::<String>("in").map(|s| s.as_str());
        let signature_file = matches
            .get_one::<String>("signature_file")
            .map(|s| s.as_str());
        let splits = matches.get_one::<String>("splits").map(|s| s.as_str());
        let signed_sections_rx = match splits {
            None => None,
            Some(splits) => Some(
                RegexBuilder::new(splits)
                    .case_insensitive(false)
                    .multi_line(false)
                    .dot_matches_new_line(false)
                    .size_limit(1_000_000)
                    .dfa_size_limit(1_000_000)
                    .nest_limit(1000)
                    .build()
                    .map_err(|_| WSError::InvalidArgument)?,
            ),
        };
        let pk_files = matches
            .get_many::<String>("public_keys")
            .ok_or(WSError::UsageError("Missing public key files"))?;
        let mut pks_set = std::collections::HashSet::new();
        for pk_file in pk_files {
            let pk = PublicKey::from_file(pk_file)?;
            pks_set.insert(pk);
        }
        let pks = PublicKeySet::new(pks_set).attach_default_key_id();
        let input_file = input_file.ok_or(WSError::UsageError("Missing input file"))?;
        let mut detached_signatures_ = vec![];
        let detached_signatures = match signature_file {
            None => None,
            Some(signature_file) => {
                open_file(signature_file)?.read_to_end(&mut detached_signatures_)?;
                Some(detached_signatures_.as_slice())
            }
        };
        let mut reader = BufReader::new(open_file(input_file)?);
        let predicates: Vec<BoxedPredicate> = if let Some(signed_sections_rx) = signed_sections_rx {
            vec![Box::new(move |section| match section {
                Section::Standard(_) => true,
                Section::Custom(custom_section) => {
                    signed_sections_rx.is_match(custom_section.name())
                }
            })]
        } else {
            vec![Box::new(|_| true)]
        };
        let matrix = pks.verify_matrix(&mut reader, detached_signatures, &predicates)?;
        let valid_pks = matrix.first().ok_or(WSError::UsageError("No predicates"))?;
        if valid_pks.is_empty() {
            println!("No valid public keys found");
        } else {
            println!("Valid public keys:");
            for pk in valid_pks {
                println!("  - {pk:x?}");
            }
        }
    } else if let Some(matches) = matches.subcommand_matches("bundle") {
        handle_bundle_command(matches, verbose)?;
    } else if let Some(matches) = matches.subcommand_matches("show-chain") {
        handle_show_chain_command(matches)?;
    } else if let Some(matches) = matches.subcommand_matches("verify-chain") {
        handle_verify_chain_command(matches)?;
    } else if let Some(matches) = matches.subcommand_matches("attest") {
        handle_attest_command(matches)?;
    } else {
        return Err(WSError::UsageError("No subcommand specified"));
    }
    Ok(())
}

/// Handle bundle subcommands
fn handle_bundle_command(matches: &clap::ArgMatches, verbose: bool) -> Result<(), WSError> {
    if let Some(matches) = matches.subcommand_matches("create") {
        // bundle create
        let output_file = matches
            .get_one::<String>("out")
            .map(|s| s.as_str())
            .ok_or(WSError::UsageError("Missing output file"))?;

        let version: u32 = matches
            .get_one::<String>("version")
            .map(|s| s.parse().unwrap_or(1))
            .unwrap_or(1);

        let validity_days: u32 = matches
            .get_one::<String>("validity_days")
            .map(|s| s.parse().unwrap_or(365))
            .unwrap_or(365);

        let mut bundle = TrustBundle::new(version, validity_days);

        // Add CA certificates if provided
        if let Some(ca_files) = matches.get_many::<String>("ca_cert") {
            for ca_file in ca_files {
                let pem = std::fs::read_to_string(ca_file).map_err(|e| {
                    WSError::InternalError(format!("Failed to read CA cert '{}': {}", ca_file, e))
                })?;
                let ca = CertificateAuthority::new(
                    ca_file, // Use filename as name
                    "",      // No URI for now
                    vec![pem],
                    validity_days,
                );
                bundle.add_certificate_authority(ca);
            }
        }

        // Add Rekor key if provided
        if let Some(rekor_file) = matches.get_one::<String>("rekor_key") {
            let pem = std::fs::read_to_string(rekor_file).map_err(|e| {
                WSError::InternalError(format!("Failed to read Rekor key '{}': {}", rekor_file, e))
            })?;
            let log = TransparencyLog::new("https://rekor.sigstore.dev", &pem, validity_days)?;
            bundle.add_transparency_log(log);
        }

        // Compute bundle ID
        bundle.compute_bundle_id()?;

        // Save bundle
        let json = bundle.to_json()?;
        create_file_with_dirs(output_file)?.write_all(&json)?;

        println!("Trust bundle created:");
        println!("  Version: {}", bundle.version);
        println!("  Format:  v{}", TRUST_BUNDLE_FORMAT_VERSION);
        println!("  Bundle ID: {}", &bundle.bundle_id[..16]);
        println!("  CAs: {}", bundle.certificate_authorities.len());
        println!("  Transparency logs: {}", bundle.transparency_logs.len());
        println!("  Valid for: {} days", validity_days);
        println!("\nSaved to: {}", output_file);
        println!("\nNote: This bundle is UNSIGNED. Use 'wsc bundle sign' to sign it.");
    } else if let Some(matches) = matches.subcommand_matches("sign") {
        // bundle sign
        let input_file = matches
            .get_one::<String>("in")
            .map(|s| s.as_str())
            .ok_or(WSError::UsageError("Missing input file"))?;

        let output_file = matches
            .get_one::<String>("out")
            .map(|s| s.as_str())
            .ok_or(WSError::UsageError("Missing output file"))?;

        let sk_file = matches
            .get_one::<String>("secret_key")
            .map(|s| s.as_str())
            .ok_or(WSError::UsageError("Missing secret key file"))?;

        // Load bundle
        let bundle_data = std::fs::read(input_file).map_err(|e| {
            WSError::InternalError(format!("Failed to read bundle '{}': {}", input_file, e))
        })?;
        let bundle = TrustBundle::from_json(&bundle_data)?;

        // Load secret key (Ed25519)
        // The wsc key format has a 1-byte prefix, so we need to strip it
        let sk = SecretKey::from_file(sk_file)?;
        let sk_bytes = sk.to_bytes();
        let raw_key = if sk_bytes.len() > 32 {
            // Skip the type prefix byte and use the seed (first 32 bytes of raw key)
            &sk_bytes[1..33]
        } else {
            &sk_bytes[..]
        };

        // Sign bundle
        let signed = SignedTrustBundle::sign(bundle, raw_key)?;

        // Save signed bundle
        let json = signed.to_json()?;
        create_file_with_dirs(output_file)?.write_all(&json)?;

        println!("Trust bundle signed:");
        println!("  Key ID: {}", signed.signature.key_id);
        println!("  Algorithm: {:?}", signed.signature.algorithm);
        println!("  Bundle version: {}", signed.bundle.version);
        println!("\nSaved to: {}", output_file);
    } else if let Some(matches) = matches.subcommand_matches("verify") {
        // bundle verify
        let input_file = matches
            .get_one::<String>("in")
            .map(|s| s.as_str())
            .ok_or(WSError::UsageError("Missing input file"))?;

        let pk_file = matches
            .get_one::<String>("public_key")
            .map(|s| s.as_str())
            .ok_or(WSError::UsageError("Missing public key file"))?;

        // Load signed bundle
        let bundle_data = std::fs::read(input_file).map_err(|e| {
            WSError::InternalError(format!("Failed to read bundle '{}': {}", input_file, e))
        })?;
        let signed = SignedTrustBundle::from_json(&bundle_data)?;

        // Load public key
        // The wsc key format has a 1-byte prefix, so we need to strip it
        let pk = PublicKey::from_file(pk_file)?;
        let pk_bytes = pk.to_bytes();
        let raw_pk = if pk_bytes.len() > 32 {
            // Skip the type prefix byte
            &pk_bytes[1..]
        } else {
            &pk_bytes[..]
        };

        // Verify signature
        signed.verify(raw_pk)?;

        println!("✓ Bundle signature is valid");
        println!("  Key ID: {}", signed.signature.key_id);
        println!("  Bundle version: {}", signed.bundle.version);

        // Check validity
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if signed.bundle.is_valid(now) {
            println!("  Status: VALID");
        } else if signed.bundle.is_in_grace_period(now) {
            println!("  Status: IN GRACE PERIOD (update bundle soon)");
        } else {
            println!("  Status: EXPIRED");
        }
    } else if let Some(matches) = matches.subcommand_matches("inspect") {
        // bundle inspect
        let input_file = matches
            .get_one::<String>("in")
            .map(|s| s.as_str())
            .ok_or(WSError::UsageError("Missing input file"))?;

        let data = std::fs::read(input_file).map_err(|e| {
            WSError::InternalError(format!("Failed to read bundle '{}': {}", input_file, e))
        })?;

        // Try to parse as signed bundle first
        let (bundle, is_signed) = if let Ok(signed) = SignedTrustBundle::from_json(&data) {
            (signed.bundle, true)
        } else {
            // Try as unsigned bundle
            let bundle = TrustBundle::from_json(&data)?;
            (bundle, false)
        };

        println!("Trust Bundle");
        println!("============");
        println!("Format version: {}", bundle.format_version);
        println!("Bundle version: {} (anti-rollback)", bundle.version);
        println!("Bundle ID: {}", bundle.bundle_id);
        println!("Signed: {}", if is_signed { "YES" } else { "NO" });
        println!();

        // Validity
        let created = chrono_format(bundle.created_at);
        let not_before = chrono_format(bundle.validity.not_before);
        let not_after = chrono_format(bundle.validity.not_after);

        println!("Validity:");
        println!("  Created: {}", created);
        println!("  Not before: {}", not_before);
        println!("  Not after: {}", not_after);
        println!(
            "  Grace period: {} days",
            bundle.validity.grace_period_seconds / 86400
        );

        // Current status
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let status = if bundle.is_valid(now) {
            "VALID"
        } else if bundle.is_in_grace_period(now) {
            "IN GRACE PERIOD"
        } else {
            "EXPIRED"
        };
        println!("  Current status: {}", status);
        println!();

        // Certificate Authorities
        println!("Certificate Authorities ({}):", bundle.certificate_authorities.len());
        for (i, ca) in bundle.certificate_authorities.iter().enumerate() {
            println!("  [{}] {}", i + 1, ca.name);
            if !ca.uri.is_empty() {
                println!("      URI: {}", ca.uri);
            }
            println!("      Certificates: {}", ca.certificates_pem.len());
            if verbose {
                for (j, pem) in ca.certificates_pem.iter().enumerate() {
                    let lines: Vec<&str> = pem.lines().collect();
                    println!(
                        "        [{}] {} lines",
                        j + 1,
                        lines.len()
                    );
                }
            }
        }
        println!();

        // Transparency Logs
        println!("Transparency Logs ({}):", bundle.transparency_logs.len());
        for (i, log) in bundle.transparency_logs.iter().enumerate() {
            println!("  [{}] {}", i + 1, log.base_url);
            println!("      Log ID: {}...", &log.log_id[..16.min(log.log_id.len())]);
            println!("      Algorithm: {}", log.hash_algorithm);
        }
        println!();

        // Revocations
        if !bundle.revocations.is_empty() {
            println!("Revocations ({}):", bundle.revocations.len());
            for rev in &bundle.revocations {
                println!("  - {}...", &rev[..16.min(rev.len())]);
            }
        } else {
            println!("Revocations: (none)");
        }
    } else if let Some(matches) = matches.subcommand_matches("fetch") {
        // bundle fetch - fetch from Sigstore TUF
        let output_file = matches
            .get_one::<String>("out")
            .map(|s| s.as_str())
            .ok_or(WSError::UsageError("Missing output file"))?;

        let version: u32 = matches
            .get_one::<String>("version")
            .map(|s| s.parse().unwrap_or(1))
            .unwrap_or(1);

        let validity_days: u32 = matches
            .get_one::<String>("validity_days")
            .map(|s| s.parse().unwrap_or(90))
            .unwrap_or(90);

        let sign_key = matches.get_one::<String>("sign").map(|s| s.as_str());

        println!("Fetching trust material from Sigstore...");
        println!("  Source: {}", SIGSTORE_TRUSTED_ROOT_URL);

        // Fetch trusted root
        let trusted_root = fetch_sigstore_trusted_root()?;

        println!("  Found {} certificate authorities", trusted_root.certificate_authorities.len());
        println!("  Found {} transparency logs", trusted_root.tlogs.len());

        // Convert to TrustBundle
        let bundle = trusted_root_to_bundle(&trusted_root, version, validity_days)?;

        println!("\nTrust bundle created:");
        println!("  Version: {}", bundle.version);
        println!("  Format:  v{}", TRUST_BUNDLE_FORMAT_VERSION);
        println!("  Bundle ID: {}", &bundle.bundle_id[..16]);
        println!("  CAs: {}", bundle.certificate_authorities.len());
        println!("  Transparency logs: {}", bundle.transparency_logs.len());
        println!("  Valid for: {} days", validity_days);

        // Sign if key provided
        if let Some(sk_file) = sign_key {
            let sk = SecretKey::from_file(sk_file)?;
            let sk_bytes = sk.to_bytes();
            let raw_key = if sk_bytes.len() > 32 {
                &sk_bytes[1..33]
            } else {
                &sk_bytes[..]
            };

            let signed = SignedTrustBundle::sign(bundle, raw_key)?;
            let json = signed.to_json()?;
            create_file_with_dirs(output_file)?.write_all(&json)?;

            println!("\nBundle signed:");
            println!("  Key ID: {}", signed.signature.key_id);
            println!("  Algorithm: {:?}", signed.signature.algorithm);
        } else {
            let json = bundle.to_json()?;
            create_file_with_dirs(output_file)?.write_all(&json)?;
            println!("\nNote: Bundle is UNSIGNED. Use --sign <key> to sign it.");
        }

        println!("\nSaved to: {}", output_file);
    } else {
        return Err(WSError::UsageError(
            "Missing bundle subcommand. Use: create, sign, verify, inspect, or fetch",
        ));
    }

    Ok(())
}

/// Handle show-chain command - display transformation attestation chain
fn handle_show_chain_command(matches: &clap::ArgMatches) -> Result<(), WSError> {
    let input_file = matches
        .get_one::<String>("in")
        .map(|s| s.as_str())
        .ok_or(WSError::UsageError("Missing input file"))?;

    let as_json = matches.get_flag("json");

    // Read the module
    let module = Module::deserialize_from_file(input_file)?;

    // Try to extract audit trail first (full chain)
    if let Ok(Some(audit_trail)) = extract_transformation_audit_trail(&module) {
        if as_json {
            let json = audit_trail.to_json().map_err(|e| {
                WSError::InternalError(format!("Failed to serialize audit trail: {}", e))
            })?;
            println!("{}", json);
        } else {
            println!("Transformation Audit Trail");
            println!("==========================");
            println!("Final artifact:");
            println!("  Hash: {}", audit_trail.artifact.hash);
            println!("  Size: {} bytes", audit_trail.artifact.size);
            println!();
            println!("Transformations ({}):", audit_trail.transformations.len());
            for (i, attestation) in audit_trail.transformations.iter().enumerate() {
                println!("  [{}] {} v{}", i + 1, attestation.tool.name, attestation.tool.version);
                println!("      Type: {}", attestation.transformation_type);
                println!("      Timestamp: {}", attestation.timestamp);
                println!("      Inputs: {}", attestation.inputs.len());
                println!("      Output hash: {}", attestation.output.hash);
            }
            println!();
            println!("Root components ({}):", audit_trail.root_components.len());
            for (i, root) in audit_trail.root_components.iter().enumerate() {
                println!("  [{}] {}", i + 1, root.artifact.name);
                println!("      Hash: {}", root.artifact.hash);
                println!("      Signature: {} ({})",
                    root.signature_info.key_id.as_deref().unwrap_or("unknown"),
                    root.signature_info.algorithm);
            }
        }
        return Ok(());
    }

    // Try to extract all transformation attestations
    let attestations = extract_all_transformation_attestations(&module)?;

    if attestations.is_empty() {
        println!("No transformation attestations found in module.");
        return Ok(());
    }

    if as_json {
        let json = serde_json::to_string_pretty(&attestations).map_err(|e| {
            WSError::InternalError(format!("Failed to serialize attestations: {}", e))
        })?;
        println!("{}", json);
    } else {
        println!("Transformation Attestations");
        println!("===========================");
        for (i, attestation) in attestations.iter().enumerate() {
            println!("[{}] {} v{}", i + 1, attestation.tool.name, attestation.tool.version);
            println!("    ID: {}", attestation.attestation_id);
            println!("    Type: {}", attestation.transformation_type);
            println!("    Timestamp: {}", attestation.timestamp);
            println!("    Inputs: {}", attestation.inputs.len());
            for (j, input) in attestation.inputs.iter().enumerate() {
                println!("      [{}] {} ({})", j + 1, input.artifact.hash, input.signature_status);
            }
            println!("    Output: {}", attestation.output.hash);
            println!();
        }
    }

    Ok(())
}

/// Handle verify-chain command - verify transformation attestation chain
fn handle_verify_chain_command(matches: &clap::ArgMatches) -> Result<(), WSError> {
    let input_file = matches
        .get_one::<String>("in")
        .map(|s| s.as_str())
        .ok_or(WSError::UsageError("Missing input file"))?;

    let policy_file = matches.get_one::<String>("policy").map(|s| s.as_str());
    let trusted_tools_file = matches.get_one::<String>("trusted_tools").map(|s| s.as_str());
    let require_signatures = matches.get_flag("require_signatures");
    let require_attestation_signatures = matches.get_flag("require_attestation_signatures");
    let strict_mode = matches.get_flag("strict");
    let report_only = matches.get_flag("report_only");
    let max_age_days = matches.get_one::<String>("max_age")
        .and_then(|s| s.parse::<u64>().ok());

    // Read the module
    let module = Module::deserialize_from_file(input_file)?;

    // Extract attestation from module
    let attestation = extract_transformation_attestation(&module)?
        .ok_or(WSError::InternalError("No transformation attestation found in module".to_string()))?;

    // If a policy file is provided, use the new policy engine
    if let Some(policy_path) = policy_file {
        return handle_policy_verification(&attestation, policy_path, strict_mode, report_only);
    }

    // Build verification policy
    let mut policy = ChainVerificationPolicy::default();

    if require_signatures {
        policy.mode = ChainVerificationMode::AllInputsSigned;
    } else {
        // Default to lenient if not requiring signatures
        policy.mode = ChainVerificationMode::NoRootSignaturesRequired;
    }

    if let Some(days) = max_age_days {
        policy.max_attestation_age = Some(std::time::Duration::from_secs(days * 86400));
    }

    // Enable attestation signature verification if flag is set
    policy.verify_attestation_signatures = require_attestation_signatures;

    // Load trusted tools if specified
    if let Some(tools_file) = trusted_tools_file {
        let tools_data = std::fs::read_to_string(tools_file).map_err(|e| {
            WSError::InternalError(format!("Failed to read trusted tools '{}': {}", tools_file, e))
        })?;
        // Parse as a map of tool name -> tool config with optional public keys
        let tools_json: serde_json::Value = serde_json::from_str(&tools_data).map_err(|e| {
            WSError::InternalError(format!("Failed to parse trusted tools: {}", e))
        })?;

        if let Some(obj) = tools_json.as_object() {
            for (name, value) in obj {
                let mut info = if let Some(min_ver) = value.get("min_version").and_then(|v| v.as_str()) {
                    TrustedToolInfo::min_version(min_ver)
                } else {
                    TrustedToolInfo::any_version()
                };

                // Parse public keys if present
                // Format: "public_keys": [{"algorithm": "ed25519", "key": "base64...", "key_id": "optional"}]
                if let Some(public_keys) = value.get("public_keys").and_then(|v| v.as_array()) {
                    for pk in public_keys {
                        let algorithm = pk.get("algorithm").and_then(|v| v.as_str()).unwrap_or("ed25519");
                        if let Some(key) = pk.get("key").and_then(|v| v.as_str()) {
                            let key_id = pk.get("key_id").and_then(|v| v.as_str()).map(String::from);
                            info.public_keys.push(TrustedPublicKey {
                                algorithm: algorithm.to_string(),
                                key: key.to_string(),
                                key_id,
                            });
                        }
                    }
                }

                policy.trusted_tools.insert(name.clone(), info);
            }
        }
    }

    // Verify chain
    let result = verify_transformation_chain(&attestation, &policy);

    if result.valid {
        println!("✓ Transformation chain is valid");
        println!();
        println!("Transformation stages: {}", result.transformation_count);
        println!("Tools used: {}", result.tools_used.join(", "));
        if !result.root_components.is_empty() {
            println!();
            println!("Root components: {}", result.root_components.len());
            for (i, root) in result.root_components.iter().enumerate() {
                println!("  [{}] {}", i + 1, root);
            }
        }
        if !result.warnings.is_empty() {
            println!();
            println!("Warnings:");
            for warning in &result.warnings {
                println!("  - {}", warning);
            }
        }
    } else {
        eprintln!("✗ Transformation chain verification failed");
        if !result.errors.is_empty() {
            eprintln!();
            eprintln!("Errors:");
            for err in &result.errors {
                eprintln!("  - {}", err);
            }
        }
        return Err(WSError::VerificationFailed);
    }

    Ok(())
}

/// Handle attest command - record a transformation attestation
fn handle_attest_command(matches: &clap::ArgMatches) -> Result<(), WSError> {
    let input_file = matches
        .get_one::<String>("in")
        .map(|s| s.as_str())
        .ok_or(WSError::UsageError("Missing input file"))?;

    let output_file = matches
        .get_one::<String>("out")
        .map(|s| s.as_str())
        .ok_or(WSError::UsageError("Missing output file"))?;

    let tool_name = matches
        .get_one::<String>("tool_name")
        .map(|s| s.as_str())
        .ok_or(WSError::UsageError("Missing tool name"))?;

    let tool_version = matches
        .get_one::<String>("tool_version")
        .map(|s| s.as_str())
        .ok_or(WSError::UsageError("Missing tool version"))?;

    let transform_type = matches
        .get_one::<String>("type")
        .map(|s| s.as_str())
        .unwrap_or("custom");

    // Parse transformation type
    let transformation_type = match transform_type {
        "optimization" => TransformationType::Optimization,
        "composition" => TransformationType::Composition,
        "instrumentation" => TransformationType::Instrumentation,
        "stripping" => TransformationType::Stripping,
        _ => TransformationType::Custom,
    };

    // Read input module (the original, before transformation)
    let input_bytes = std::fs::read(input_file).map_err(|e| {
        WSError::InternalError(format!("Failed to read input '{}': {}", input_file, e))
    })?;

    // Read output module (the transformed result)
    let output_bytes = std::fs::read(output_file).map_err(|e| {
        WSError::InternalError(format!("Failed to read output '{}': {}", output_file, e))
    })?;

    // Build attestation using the builder pattern
    let builder = match transformation_type {
        TransformationType::Optimization => {
            TransformationAttestationBuilder::new_optimization(tool_name, tool_version)
        }
        TransformationType::Composition => {
            TransformationAttestationBuilder::new_composition(tool_name, tool_version)
        }
        TransformationType::Instrumentation => {
            TransformationAttestationBuilder::new_instrumentation(tool_name, tool_version)
        }
        _ => TransformationAttestationBuilder::new(transformation_type, tool_name, tool_version),
    };

    // Add input and build attestation
    let attestation = builder
        .add_input_unsigned(&input_bytes, input_file)
        .build(&output_bytes, output_file);

    // Parse output as Module and embed attestation
    let output_module = Module::deserialize_from_file(output_file)?;
    let with_attestation = embed_transformation_attestation(output_module, &attestation)?;

    // Serialize and write output with attestation
    with_attestation.serialize_to_file(output_file)?;

    // Get output file size for reporting
    let output_size = std::fs::metadata(output_file)
        .map(|m| m.len())
        .unwrap_or(0);

    println!("Transformation attestation recorded:");
    println!("  ID: {}", attestation.attestation_id);
    println!("  Tool: {} v{}", attestation.tool.name, attestation.tool.version);
    println!("  Type: {}", attestation.transformation_type);
    println!("  Input: {} ({} bytes)", input_file, input_bytes.len());
    println!("  Output: {} ({} bytes)", output_file, output_size);
    println!();
    println!("Attestation embedded in: {}", output_file);

    Ok(())
}

/// Handle policy-based verification using the new SLSA-aware policy engine
fn handle_policy_verification(
    attestation: &TransformationAttestation,
    policy_path: &str,
    strict_mode: bool,
    report_only: bool,
) -> Result<(), WSError> {
    // Load policy from TOML file
    let mut policy = Policy::from_toml_file(policy_path).map_err(|e| {
        WSError::InternalError(format!("Failed to load policy '{}': {}", policy_path, e))
    })?;

    // Apply enforcement overrides if specified
    if strict_mode {
        policy.policy.enforcement = Enforcement::Strict;
        policy.slsa.enforcement = Some(Enforcement::Strict);
        policy.signatures.enforcement = Some(Enforcement::Strict);
    } else if report_only {
        policy.policy.enforcement = Enforcement::Report;
        policy.slsa.enforcement = Some(Enforcement::Report);
        policy.signatures.enforcement = Some(Enforcement::Report);
    }

    // Evaluate the policy
    let result = evaluate_policy(attestation, &policy);

    // Display results
    println!("Policy: {} v{}", policy.policy.name, policy.policy.version);
    println!("SLSA Level: {}", result.slsa_level);
    println!();

    // Show rule results
    println!("Rule Results:");
    for rule in &result.rules {
        let icon = if rule.passed { "✓" } else { "✗" };
        let mode = match rule.enforcement {
            Enforcement::Strict => "",
            Enforcement::Report => " [report]",
        };
        println!("  {} {}{}: {}", icon, rule.rule, mode, rule.message);
        if let Some(ref details) = rule.details {
            println!("      {}", details);
        }
    }
    println!();

    // Summary
    println!("Summary:");
    println!("  Rules evaluated: {}", result.summary.total_rules);
    println!("  Passed: {}", result.summary.passed);
    if result.summary.failed_strict > 0 {
        println!("  Failed (strict): {}", result.summary.failed_strict);
    }
    if result.summary.failed_report > 0 {
        println!("  Warnings: {}", result.summary.failed_report);
    }
    if !result.summary.tools_verified.is_empty() {
        println!("  Tools verified: {}", result.summary.tools_verified.join(", "));
    }

    // SLSA improvement suggestions
    let suggestions = result.slsa_suggestions();
    if !suggestions.is_empty() {
        println!();
        println!("To reach next SLSA level:");
        for suggestion in suggestions {
            println!("  - {}", suggestion);
        }
    }

    // Overall result
    println!();
    if result.passed {
        println!("✓ Policy evaluation PASSED");
        Ok(())
    } else {
        eprintln!("✗ Policy evaluation FAILED");
        Err(WSError::VerificationFailed)
    }
}

/// Format Unix timestamp as human-readable date
fn chrono_format(timestamp: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let dt = UNIX_EPOCH + Duration::from_secs(timestamp);
    // Format as ISO 8601 using stdlib
    let duration = dt
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let days = secs / 86400;
    // Approximate date from days since epoch
    let year = 1970 + (days / 365);
    let remaining_days = days % 365;
    let month = remaining_days / 30 + 1;
    let day = remaining_days % 30 + 1;
    format!("{:04}-{:02}-{:02}", year, month.min(12), day.min(31))
}

fn main() -> Result<(), WSError> {
    let res = start();
    match res {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
    Ok(())
}
