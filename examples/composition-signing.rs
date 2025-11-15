/// Example: Signing composed WASM components
///
/// This demonstrates the programmatic workflow for:
/// 1. Signing individual components (owner)
/// 2. Composing components (external wac tool)
/// 3. Signing composed result (integrator)
/// 4. Verifying all signatures
///
/// Run with:
///   cargo run --example composition-signing

use std::fs;
use std::process::Command;
use wsc::error::WSError;
use wsc::platform::SoftwareProvider;
use wsc::provisioning::*;
use wsc::wasm_module::Module;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== WASM Component Composition Workflow ===\n");

    // Setup: Create CAs and provision devices
    println!("Setting up PKI infrastructure...");
    let (owner_ca, owner_provider, owner_key) = setup_owner_pki()?;
    let (integrator_ca, integrator_provider, integrator_key) = setup_integrator_pki()?;
    println!("✓ PKI setup complete\n");

    // Step 1: Owner signs individual components
    println!("Step 1: Owner signs components A and B");
    let signed_a = sign_component(
        "examples/components/component-a.wasm",
        &owner_ca,
        &owner_provider,
        owner_key,
        "component-a-signed.wasm",
    )?;
    let signed_b = sign_component(
        "examples/components/component-b.wasm",
        &owner_ca,
        &owner_provider,
        owner_key,
        "component-b-signed.wasm",
    )?;
    println!("✓ Both components signed by owner\n");

    // Step 2: Compose with wac (external tool)
    println!("Step 2: Composing components with wac");
    let composed_path = compose_with_wac(&[
        "component-a-signed.wasm",
        "component-b-signed.wasm",
    ])?;
    println!("✓ Components composed into: {}\n", composed_path);

    // Step 3: Create composition manifest
    println!("Step 3: Creating composition manifest");
    let manifest = CompositionManifest {
        version: "1.0".to_string(),
        tool: "wac".to_string(),
        components: vec![
            ComponentInfo {
                id: "component-a".to_string(),
                hash: compute_hash("examples/components/component-a.wasm")?,
                signer: "CN=Owner Device, O=Owner Corp".to_string(),
            },
            ComponentInfo {
                id: "component-b".to_string(),
                hash: compute_hash("examples/components/component-b.wasm")?,
                signer: "CN=Owner Device, O=Owner Corp".to_string(),
            },
        ],
    };
    save_manifest(&manifest, "composition-manifest.json")?;
    println!("✓ Manifest created\n");

    // Step 4: Integrator signs composed component
    println!("Step 4: Integrator signs composed component");
    sign_composed_component(
        &composed_path,
        &integrator_ca,
        &integrator_provider,
        integrator_key,
        "composed-dual-signed.wasm",
    )?;
    println!("✓ Composed component signed by integrator\n");

    // Step 5: Verify all signatures
    println!("Step 5: Verifying all signatures");
    verify_all_signatures(
        "composed-dual-signed.wasm",
        &owner_ca,
        &integrator_ca,
    )?;
    println!("✓ All signatures verified!\n");

    // Step 6: Inspect signatures
    println!("Step 6: Inspecting signatures");
    inspect_all_signatures("composed-dual-signed.wasm")?;

    println!("\n=== Workflow Complete ===");
    println!("Final artifact: composed-dual-signed.wasm");
    println!("Manifest: composition-manifest.json");
    println!("✓ Ready for deployment!");

    Ok(())
}

/// Setup owner PKI and provision device
fn setup_owner_pki() -> Result<(PrivateCA, SoftwareProvider, KeyHandle), WSError> {
    let ca_config = CAConfig::new("Owner Corp", "Owner Root CA");
    let ca = PrivateCA::create_root(ca_config)?;

    let provider = SoftwareProvider::new();
    let device_id = DeviceIdentity::new("owner-device-001");
    let cert_config = CertificateConfig::new("owner-device-001");

    let prov_result = ProvisioningSession::provision(
        &ca,
        &provider,
        device_id,
        cert_config,
        false, // Don't lock key (software provider)
    )?;

    Ok((ca, provider, prov_result.key_handle))
}

/// Setup integrator PKI and provision device
fn setup_integrator_pki() -> Result<(PrivateCA, SoftwareProvider, KeyHandle), WSError> {
    let ca_config = CAConfig::new("Integrator Inc", "Integrator Root CA");
    let ca = PrivateCA::create_root(ca_config)?;

    let provider = SoftwareProvider::new();
    let device_id = DeviceIdentity::new("integrator-device-001");
    let cert_config = CertificateConfig::new("integrator-device-001");

    let prov_result = ProvisioningSession::provision(
        &ca,
        &provider,
        device_id,
        cert_config,
        false,
    )?;

    Ok((ca, provider, prov_result.key_handle))
}

/// Sign a component with certificate
fn sign_component(
    input_path: &str,
    ca: &PrivateCA,
    provider: &SoftwareProvider,
    key_handle: KeyHandle,
    output_path: &str,
) -> Result<String, WSError> {
    // For testing, use full keypair
    let keypair = provider.export_keypair(key_handle)?;
    let device_id = DeviceIdentity::new("device");
    let cert_config = CertificateConfig::new("device");

    let device_cert = ca.sign_device_certificate_with_keypair(
        &keypair,
        &device_id,
        &cert_config,
    )?;

    let cert_chain = vec![device_cert, ca.certificate().to_vec()];

    // Load and sign component
    let component = Module::deserialize_from_file(input_path)?;
    let signed = sign_with_certificate(
        provider,
        key_handle,
        component,
        &cert_chain,
    )?;

    // Save signed component
    signed.serialize_to_file(output_path)?;

    Ok(output_path.to_string())
}

/// Compose components using wac (external tool)
fn compose_with_wac(components: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let output = "composed.wasm";

    // Call wac as subprocess
    let mut cmd = Command::new("wac");
    cmd.arg("compose");
    cmd.arg("--output").arg(output);
    for component in components {
        cmd.arg(component);
    }

    let status = cmd.status()?;
    if !status.success() {
        return Err("wac composition failed".into());
    }

    Ok(output.to_string())
}

/// Sign an already-composed component (adds integrator signature)
fn sign_composed_component(
    composed_path: &str,
    ca: &PrivateCA,
    provider: &SoftwareProvider,
    key_handle: KeyHandle,
    output_path: &str,
) -> Result<(), WSError> {
    // For testing, use full keypair
    let keypair = provider.export_keypair(key_handle)?;
    let device_id = DeviceIdentity::new("integrator-device");
    let cert_config = CertificateConfig::new("integrator-device");

    let device_cert = ca.sign_device_certificate_with_keypair(
        &keypair,
        &device_id,
        &cert_config,
    )?;

    let cert_chain = vec![device_cert, ca.certificate().to_vec()];

    // Load composed component
    let composed = Module::deserialize_from_file(composed_path)?;

    // Add integrator signature (preserves owner signatures)
    let dual_signed = sign_with_certificate(
        provider,
        key_handle,
        composed,
        &cert_chain,
    )?;

    // Save dual-signed component
    dual_signed.serialize_to_file(output_path)?;

    Ok(())
}

/// Verify all signatures in a composed component
fn verify_all_signatures(
    wasm_path: &str,
    owner_ca: &PrivateCA,
    integrator_ca: &PrivateCA,
) -> Result<(), WSError> {
    let mut wasm_file = fs::File::open(wasm_path)?;

    // Create verifiers for both PKI hierarchies
    let owner_verifier = OfflineVerifierBuilder::new()
        .with_root(owner_ca.certificate())?
        .build()?;

    let integrator_verifier = OfflineVerifierBuilder::new()
        .with_root(integrator_ca.certificate())?
        .build()?;

    // Verify all signatures
    let results = verify_all_certificates(
        &mut wasm_file,
        &[&owner_verifier, &integrator_verifier],
    )?;

    println!("Found {} signatures:", results.len());
    for result in &results {
        if result.verified {
            println!("  ✓ Signature {}: {} certificates",
                result.info.index,
                result.info.certificate_count
            );
        } else {
            println!("  ✗ Signature {}: FAILED - {:?}",
                result.info.index,
                result.error
            );
        }
    }

    // Check all verified
    let all_verified = results.iter().all(|r| r.verified);
    if !all_verified {
        return Err(WSError::VerificationFailed);
    }

    Ok(())
}

/// Inspect all signatures without verifying
fn inspect_all_signatures(wasm_path: &str) -> Result<(), WSError> {
    let mut wasm_file = fs::File::open(wasm_path)?;
    let signatures = inspect_signatures(&mut wasm_file)?;

    println!("\nSignature Details:");
    println!("Total signatures: {}", signatures.len());
    for sig in signatures {
        println!("\nSignature {}:", sig.index);
        println!("  Certificate chain: {}", sig.has_certificate_chain);
        println!("  Certificate count: {}", sig.certificate_count);
        if let Some(dn) = sig.subject_dn {
            println!("  Subject: {}", dn);
        }
        if let Some(key_id) = sig.key_id {
            println!("  Key ID: {}", hex::encode(key_id));
        }
    }

    Ok(())
}

/// Compute SHA-256 hash of a file
fn compute_hash(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    use sha2::{Sha256, Digest};
    let bytes = fs::read(path)?;
    let hash = Sha256::digest(&bytes);
    Ok(hex::encode(hash))
}

/// Composition manifest structure
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CompositionManifest {
    version: String,
    tool: String,
    components: Vec<ComponentInfo>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ComponentInfo {
    id: String,
    hash: String,
    signer: String,
}

/// Save manifest to JSON file
fn save_manifest(manifest: &CompositionManifest, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(manifest)?;
    fs::write(path, json)?;
    Ok(())
}
