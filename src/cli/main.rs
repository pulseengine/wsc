use wsc::{BoxedPredicate, KeyPair, Module, PublicKey, PublicKeySet, SecretKey, Section, WSError};
use wsc::airgapped::{
    CertificateAuthority, SignedTrustBundle, TransparencyLog, TrustBundle,
    TRUST_BUNDLE_FORMAT_VERSION,
    fetch_sigstore_trusted_root, trusted_root_to_bundle, SIGSTORE_TRUSTED_ROOT_URL,
};

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
                        .help("Public key file"),
                )
                .arg(
                    Arg::new("ssh")
                        .long("ssh")
                        .short('Z')
                        .action(ArgAction::SetTrue)
                        .help("Parse OpenSSH keys"),
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
                        .conflicts_with_all(["public_key", "from_github", "ssh", "signature_file", "splits"])
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
                        .help("Public key file"),
                )
                .arg(
                    Arg::new("from_github")
                        .value_name("from_github")
                        .long("from-github")
                        .short('G')
                        .required(false)
                        .help("GitHub account to retrieve public keys from"),
                )
                .arg(
                    Arg::new("ssh")
                        .long("ssh")
                        .short('Z')
                        .action(ArgAction::SetTrue)
                        .help("Parse OpenSSH keys"),
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
                        .help("Public key files"),
                )
                .arg(
                    Arg::new("from_github")
                        .value_name("from_github")
                        .long("from-github")
                        .short('G')
                        .required(false)
                        .help("GitHub account to retrieve public keys from"),
                )
                .arg(
                    Arg::new("ssh")
                        .long("ssh")
                        .short('Z')
                        .action(ArgAction::SetTrue)
                        .help("Parse OpenSSH keys"),
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
        .get_matches();

    let verbose = matches.get_flag("verbose");
    let debug = matches.get_flag("debug");

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
            let sk = match matches.get_flag("ssh") {
                false => SecretKey::from_file(sk_file)?,
                true => SecretKey::from_openssh_file(sk_file)?,
            };
            let pk_file = matches.get_one::<String>("public_key").map(|s| s.as_str());
            let key_id = if let Some(pk_file) = pk_file {
                let pk = match matches.get_flag("ssh") {
                    false => PublicKey::from_file(pk_file)?,
                    true => PublicKey::from_openssh_file(pk_file)?,
                }
                .attach_default_key_id();
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
            let pk = if let Some(github_account) =
                matches.get_one::<String>("from_github").map(|s| s.as_str())
            {
                PublicKey::from_openssh(&get_pks_from_github(github_account)?)?
            } else {
                let pk_file = matches
                    .get_one::<String>("public_key")
                    .map(|s| s.as_str())
                    .ok_or(WSError::UsageError("Missing public key file"))?;
                match matches.get_flag("ssh") {
                    false => PublicKey::from_file(pk_file)?,
                    true => PublicKey::from_openssh_file(pk_file)?,
                }
            }
            .attach_default_key_id();
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
        let pks = if let Some(github_account) =
            matches.get_one::<String>("from_github").map(|s| s.as_str())
        {
            PublicKeySet::from_openssh(&get_pks_from_github(github_account)?)?
        } else {
            let pk_files = matches
                .get_many::<String>("public_keys")
                .ok_or(WSError::UsageError("Missing public key files"))?;
            match matches.get_flag("ssh") {
                false => {
                    let mut pks = std::collections::HashSet::new();
                    for pk_file in pk_files {
                        let pk = PublicKey::from_file(pk_file)?;
                        pks.insert(pk);
                    }
                    PublicKeySet::new(pks)
                }
                true => PublicKeySet::from_openssh_file(
                    pk_files
                        .into_iter()
                        .next()
                        .ok_or(WSError::UsageError("Missing public keys file"))?,
                )?,
            }
        }
        .attach_default_key_id();
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

// Native builds: Use ureq HTTP client
#[cfg(not(target_os = "wasi"))]
fn get_pks_from_github(account: impl AsRef<str>) -> Result<String, WSError> {
    let account_rawurlencoded = uri_encode::encode_uri_component(account.as_ref());
    let url = format!("https://github.com/{account_rawurlencoded}.keys");
    let response = ureq::get(&url)
        .call()
        .map_err(|_| WSError::UsageError("Keys couldn't be retrieved from GitHub"))?;
    let s = response
        .into_body()
        .read_to_vec()
        .map_err(|_| WSError::UsageError("Keys couldn't be retrieved from GitHub"))?;
    String::from_utf8(s).map_err(|_| {
        WSError::UsageError("Unexpected characters in the public keys retrieved from GitHub")
    })
}

// WASI builds: Use wasi::http outgoing-handler
#[cfg(target_os = "wasi")]
fn get_pks_from_github(account: impl AsRef<str>) -> Result<String, WSError> {
    use wasi::http::outgoing_handler;
    use wasi::http::types::{Fields, Method, OutgoingRequest, Scheme};

    // Construct the URL for GitHub keys API
    let account_encoded = account.as_ref().replace('/', "%2F");

    // Parse URL components
    let authority = "github.com";
    let path = format!("/{}.keys", account_encoded);

    // Create outgoing request
    let headers = Fields::new();
    let request = OutgoingRequest::new(headers);
    request
        .set_method(&Method::Get)
        .map_err(|_| WSError::UsageError("Failed to set HTTP method"))?;
    request
        .set_scheme(Some(&Scheme::Https))
        .map_err(|_| WSError::UsageError("Failed to set HTTPS scheme"))?;
    request
        .set_authority(Some(authority))
        .map_err(|_| WSError::UsageError("Failed to set authority"))?;
    request
        .set_path_with_query(Some(&path))
        .map_err(|_| WSError::UsageError("Failed to set path"))?;

    // Send request
    let future_response = outgoing_handler::handle(request, None)
        .map_err(|_| WSError::UsageError("Failed to send HTTP request"))?;

    // Wait for response
    let incoming_response = future_response
        .get()
        .ok_or_else(|| WSError::UsageError("HTTP request not ready"))?
        .map_err(|_| WSError::UsageError("Keys couldn't be retrieved from GitHub"))??;

    // Read response body
    let body = incoming_response
        .consume()
        .map_err(|_| WSError::UsageError("Failed to get response body"))?;

    let mut bytes = Vec::new();
    let stream = body
        .stream()
        .map_err(|_| WSError::UsageError("Failed to get body stream"))?;

    loop {
        let chunk = stream
            .blocking_read(8192)
            .map_err(|_| WSError::UsageError("Failed to read from stream"))?;

        if chunk.is_empty() {
            break;
        }
        bytes.extend_from_slice(&chunk);
    }

    String::from_utf8(bytes).map_err(|_| {
        WSError::UsageError("Unexpected characters in the public keys retrieved from GitHub")
    })
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
