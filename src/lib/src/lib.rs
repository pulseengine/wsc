//! A proof of concept implementation of the WebAssembly module signature proposal.

// The `PublicKey::verify()` function is what most runtimes should use or reimplement if they don't need partial verification.
// The `SecretKey::sign()` function is what most 3rd-party signing tools can use or reimplement if they don't need support for multiple signatures.

#![allow(clippy::vec_init_then_push)]
// Deny unsafe code, but allow override in specific modules (e.g., allocator)
#![deny(unsafe_code)]

mod error;
mod signature;
mod split;
mod wasm_module;

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

// Phase-locked allocator for allocation-free verification
#[cfg(feature = "allocation-guard")]
pub mod allocator;

pub mod reexports {
    pub use {anyhow, ct_codecs, getrandom, hmac_sha256, log, regex, thiserror};
}

const SIGNATURE_WASM_DOMAIN: &str = "wasmsig";
const SIGNATURE_VERSION: u8 = 0x01;
const SIGNATURE_WASM_MODULE_CONTENT_TYPE: u8 = 0x01;
const SIGNATURE_HASH_FUNCTION: u8 = 0x01;
