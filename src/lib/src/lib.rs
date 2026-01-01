//! A proof of concept implementation of the WebAssembly module signature proposal.

// The `PublicKey::verify()` function is what most runtimes should use or reimplement if they don't need partial verification.
// The `SecretKey::sign()` function is what most 3rd-party signing tools can use or reimplement if they don't need support for multiple signatures.

#![allow(clippy::vec_init_then_push)]
#![forbid(unsafe_code)]

mod error;
mod signature;
mod split;
mod wasm_module;

/// Secure file operations with restrictive permissions
///
/// Provides utilities for securely reading and writing sensitive files
/// such as private keys and tokens. On Unix systems, it enforces restrictive
/// permissions (0600 = owner read/write only) to prevent credential theft.
pub mod secure_file;

/// Time validation for offline-first verification
///
/// Provides time source abstraction for embedded and edge devices that may not
/// have reliable system clocks. Supports multiple strategies including build-time
/// lower bounds and custom time sources (RTC, GPS, NTP).
pub mod time;

/// Platform-specific hardware security integration
///
/// Provides unified interface for hardware-backed cryptographic operations
/// across TPM 2.0, Secure Elements, TrustZone, and software fallback.
pub mod platform;

/// Certificate provisioning for IoT devices
///
/// Provides tools for offline certificate provisioning in factory/manufacturing
/// environments. Includes CA management, device identity, and provisioning workflows.
pub mod provisioning;

/// Component composition and provenance tracking
///
/// Provides support for WebAssembly component composition with full provenance
/// tracking, enabling supply chain security and compliance with SLSA, in-toto,
/// and SBOM standards.
pub mod composition;

/// Air-gapped verification for embedded devices
///
/// Enables offline verification of Sigstore keyless signatures using
/// pre-provisioned trust bundles. Designed for IoT, automotive, and
/// edge devices without network access at runtime.
pub mod airgapped;

#[allow(unused_imports)]
pub use error::*;
#[allow(unused_imports)]
pub use signature::*;
#[allow(unused_imports)]
pub use split::*;
#[allow(unused_imports)]
pub use wasm_module::*;

// Re-export keyless module for public API
pub use signature::keyless;

pub mod reexports {
    pub use {anyhow, ct_codecs, getrandom, hmac_sha256, log, regex, thiserror};
}

const SIGNATURE_WASM_DOMAIN: &str = "wasmsig";
const SIGNATURE_VERSION: u8 = 0x01;
const SIGNATURE_WASM_MODULE_CONTENT_TYPE: u8 = 0x01;
const SIGNATURE_HASH_FUNCTION: u8 = 0x01;
