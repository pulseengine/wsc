//! Wasmtime Component Loader with WSC Signature Verification
//!
//! This example demonstrates how to integrate WSC signature verification
//! into a Wasmtime-based component loader.
//!
//! # Usage
//!
//! ```bash
//! # Load and verify a signed component (strict mode)
//! cargo run --release -- components/hello.wasm
//!
//! # Load with warnings for unsigned components (lenient mode)
//! cargo run --release -- --lenient components/hello.wasm
//!
//! # Skip verification entirely (not recommended)
//! cargo run --release -- --no-verify components/hello.wasm
//! ```

use anyhow::{Context, Result};
use std::path::Path;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};
use wsc::signature::PublicKeySet;

/// Verification policy for component loading
#[derive(Debug, Clone, Copy)]
enum VerificationPolicy {
    /// Require valid signature (recommended for production)
    Strict,
    /// Warn on missing/invalid signature but allow loading
    Lenient,
    /// Skip verification entirely (development only)
    Disabled,
}

/// Load a WebAssembly component with signature verification
fn load_verified_component(
    engine: &Engine,
    path: &Path,
    keys: &PublicKeySet,
    policy: VerificationPolicy,
) -> Result<Component> {
    log::info!("Loading component: {}", path.display());

    // Read component bytes
    let bytes = std::fs::read(path)
        .with_context(|| format!("Failed to read component: {}", path.display()))?;

    log::debug!("Component size: {} bytes", bytes.len());

    // Verify signature based on policy
    match policy {
        VerificationPolicy::Strict => {
            log::info!("Verifying signature (strict mode)");
            keys.verify(&bytes).with_context(|| {
                format!(
                    "Signature verification failed for: {}\n\
                     Component must have a valid signature from a trusted key.\n\
                     Use --lenient to load unsigned components with a warning.",
                    path.display()
                )
            })?;
            log::info!("✓ Signature verified successfully");
        }
        VerificationPolicy::Lenient => {
            log::info!("Verifying signature (lenient mode)");
            match keys.verify(&bytes) {
                Ok(_) => {
                    log::info!("✓ Signature verified successfully");
                }
                Err(e) => {
                    log::warn!("⚠ No valid signature found: {}", e);
                    log::warn!("  Loading anyway (lenient mode)");
                }
            }
        }
        VerificationPolicy::Disabled => {
            log::warn!("⚠ Signature verification disabled (not recommended)");
        }
    }

    // Parse and validate component
    Component::new(engine, &bytes)
        .with_context(|| format!("Failed to parse component: {}", path.display()))
}

/// Simple host implementation that provides a print function
struct HostState;

fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Parse command line arguments
    let mut args = std::env::args().skip(1);
    let mut policy = VerificationPolicy::Strict;
    let mut component_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--strict" => policy = VerificationPolicy::Strict,
            "--lenient" => policy = VerificationPolicy::Lenient,
            "--no-verify" => policy = VerificationPolicy::Disabled,
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            path if !path.starts_with("--") => {
                component_path = Some(path.to_string());
            }
            _ => {
                anyhow::bail!("Unknown option: {}\nUse --help for usage information", arg);
            }
        }
    }

    let component_path = component_path
        .ok_or_else(|| anyhow::anyhow!("Missing component path\nUse --help for usage information"))?;

    log::info!("Wasmtime Component Loader with WSC Verification");
    log::info!("Policy: {:?}", policy);

    // Load trusted public keys
    log::info!("Loading trusted keys");
    let mut keys = PublicKeySet::empty();

    // Try to load keys from keys/ directory
    let key_path = Path::new("examples/wasmtime-loader/keys/trusted.pub");
    if key_path.exists() {
        keys.insert_from_file(key_path)
            .with_context(|| format!("Failed to load key: {}", key_path.display()))?;
        log::info!("Loaded {} trusted key(s)", keys.items().count());
    } else {
        log::warn!("No trusted keys found at: {}", key_path.display());
        log::warn!("All signature verifications will fail in strict mode");
        log::warn!("Generate keys with: cargo run --bin wsc -- generate-key");
    }

    // Configure Wasmtime
    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;

    // Load and verify component
    let component = load_verified_component(
        &engine,
        Path::new(&component_path),
        &keys,
        policy,
    )?;

    log::info!("✓ Component loaded successfully");

    // Create store and linker
    let mut store = Store::new(&engine, HostState);
    let mut linker = Linker::new(&engine);

    // Provide host "print" function
    linker
        .root()
        .func_wrap("host", "print", |mut _caller, (s,): (String,)| {
            println!("Component says: {}", s);
            Ok(())
        })?;

    // Instantiate the component
    log::info!("Instantiating component");
    let _instance = linker.instantiate(&mut store, &component)?;

    log::info!("✓ Component executed successfully");

    Ok(())
}

fn print_usage() {
    println!(
        "Wasmtime Component Loader with WSC Signature Verification

USAGE:
    loader [OPTIONS] <COMPONENT>

OPTIONS:
    --strict      Require valid signature (default, recommended for production)
    --lenient     Warn on missing signature but allow loading (development)
    --no-verify   Skip verification entirely (not recommended)
    -h, --help    Print this help message

EXAMPLES:
    # Load a signed component (strict mode)
    cargo run --release -- components/hello.wasm

    # Load with lenient verification
    cargo run --release -- --lenient components/hello.wasm

    # Skip verification (development only)
    cargo run --release -- --no-verify components/hello.wasm

TRUST CONFIGURATION:
    Place trusted public keys in: examples/wasmtime-loader/keys/trusted.pub
    Generate keys with: cargo run --bin wsc -- generate-key

SEE ALSO:
    https://github.com/pulseengine/wsc - WSC signature toolkit
    "
    );
}
