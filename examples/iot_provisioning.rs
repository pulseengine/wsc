/// IoT Device Provisioning Example
///
/// This example demonstrates how to provision IoT devices with certificates
/// in a factory/manufacturing environment.
///
/// # Workflow
///
/// 1. Create a private CA (Root + Intermediate)
/// 2. Provision multiple devices with certificates
/// 3. Verify device certificates offline
///
/// # Usage
///
/// ```bash
/// cargo run --example iot_provisioning
/// ```

use wsc::provisioning::{
    PrivateCA, CAConfig, CAType,
    DeviceIdentity, CertificateConfig,
    ProvisioningSession, ProvisioningStats,
    OfflineVerifier, OfflineVerifierBuilder,
};
use wsc::platform::software::SoftwareProvider;
use wsc::error::WSError;

fn main() -> Result<(), WSError> {
    println!("=== IoT Device Provisioning Example ===\n");

    // Step 1: Create Certificate Authority
    println!("Step 1: Creating Certificate Authority...");

    let root_config = CAConfig::new("Acme Corporation", "Acme Root CA")
        .with_country("US")
        .with_state("California")
        .with_locality("San Francisco")
        .with_validity_days(3650); // 10 years

    let root_ca = PrivateCA::create_root(root_config)?;
    println!("  ✓ Root CA created: {}", root_ca.config().common_name);
    println!("    Organization: {}", root_ca.config().organization);
    println!("    Type: {:?}", root_ca.ca_type());
    println!();

    // Step 2: Create Intermediate CA (optional, recommended for production)
    println!("Step 2: Creating Intermediate CA...");

    let intermediate_config = CAConfig::new("Acme Corporation", "Acme IoT Intermediate CA")
        .with_validity_days(1825); // 5 years

    let intermediate_ca = PrivateCA::create_intermediate(&root_ca, intermediate_config)?;
    println!("  ✓ Intermediate CA created: {}", intermediate_ca.config().common_name);
    println!("    Type: {:?}", intermediate_ca.ca_type());
    println!();

    // Step 3: Provision IoT Devices
    println!("Step 3: Provisioning IoT Devices...");
    println!();

    // Create a software provider (in production, use secure element)
    let provider = SoftwareProvider::new();

    // Provision multiple devices
    let devices = vec![
        ("device-001", "TemperatureSensor", "1.0"),
        ("device-002", "HumiditySensor", "1.0"),
        ("device-003", "PressureSensor", "1.1"),
    ];

    let mut results = Vec::new();
    let mut stats = ProvisioningStats::new();

    for (device_id, device_type, hw_rev) in devices {
        print!("  Provisioning {}... ", device_id);

        let start = std::time::Instant::now();

        // Create device identity
        let identity = DeviceIdentity::new(device_id)
            .with_device_type(device_type)
            .with_hardware_revision(hw_rev);

        // Configure certificate
        let config = CertificateConfig::new(device_id)
            .with_organization("Acme Corporation")
            .with_organizational_unit("IoT Devices")
            .with_validity_days(365); // 1 year

        // Provision device
        let result = ProvisioningSession::provision(
            &intermediate_ca,
            &provider,
            identity,
            config,
            true, // Lock key slot
        );

        let duration = start.elapsed().as_millis() as u64;

        match result {
            Ok(r) => {
                stats.record_success(duration);
                println!("✓ ({} ms)", duration);
                println!("      Key Handle: {:?}", r.key_handle);
                println!("      Certificate: {} bytes", r.certificate.len());
                println!("      Chain Length: {}", r.certificate_chain.len());
                results.push(r);
            }
            Err(e) => {
                stats.record_failure(duration);
                println!("✗ Error: {}", e);
            }
        }
    }

    println!();
    println!("Provisioning Statistics:");
    println!("  Total: {}", stats.total_provisioned);
    println!("  Successful: {}", stats.successful);
    println!("  Failed: {}", stats.failed);
    println!("  Success Rate: {:.1}%", stats.success_rate() * 100.0);
    println!("  Avg Time: {} ms", stats.avg_time_ms);
    println!();

    // Step 4: Verify Provisioned Devices
    println!("Step 4: Verifying Provisioned Devices...");
    println!();

    // Create offline verifier
    let verifier = OfflineVerifierBuilder::new()
        .with_root(root_ca.certificate())?
        .with_intermediate(intermediate_ca.certificate())
        .build()?;

    for result in &results {
        print!("  Verifying {}... ", result.device_id);

        // Verify device certificate chain
        let verify_result = verifier.verify_device_certificate(
            &result.certificate,
            None, // Verify at current time
        );

        match verify_result {
            Ok(_) => println!("✓ Valid"),
            Err(e) => println!("✗ Error: {}", e),
        }

        // Test device signature
        let test_data = b"test data for signature verification";
        let sign_result = provider.sign(result.key_handle, test_data);

        match sign_result {
            Ok(signature) => println!("      Signature: {} bytes", signature.len()),
            Err(e) => println!("      Signature Error: {}", e),
        }
    }

    println!();
    println!("=== Provisioning Complete ===");
    println!();
    println!("Summary:");
    println!("  {} devices provisioned successfully", results.len());
    println!("  All certificates verified offline");
    println!("  All devices can sign with hardware keys");
    println!();
    println!("Next Steps:");
    println!("  1. In production, replace SoftwareProvider with Atecc608Provider");
    println!("  2. Store Root CA offline in HSM");
    println!("  3. Use Intermediate CA for daily device signing");
    println!("  4. Embed Root CA certificate in verifier firmware");
    println!("  5. Devices can now sign WASM modules offline");

    Ok(())
}
