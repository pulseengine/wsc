//! Air-gapped verification for embedded devices
//!
//! This module enables offline verification of Sigstore keyless signatures
//! on devices without network access. It uses a **Trust Bundle** - a signed,
//! versioned container of trust anchors (Fulcio roots, Rekor keys) that is
//! provisioned to devices at manufacturing or via secure update.
//!
//! # Architecture
//!
//! ```text
//! SIGNING (CI - Online)              VERIFICATION (Device - Offline)
//! ─────────────────────              ────────────────────────────────
//!
//! GitHub Actions                     Embedded Device
//! (OIDC → Fulcio → Rekor)           ┌─────────────────────────────┐
//!         │                         │  Trust Bundle (provisioned) │
//!         ▼                         │  • Fulcio root certs        │
//! ┌─────────────────┐               │  • Rekor public key         │
//! │  Signed WASM    │  distribute   │  • Bundle version           │
//! │  • Signature    │ ───────────►  └─────────────┬───────────────┘
//! │  • Cert chain   │                             │ verifies
//! │  • Rekor entry  │                             ▼
//! └─────────────────┘               ┌─────────────────────────────┐
//!                                   │  Signed WASM (verified)     │
//!                                   └─────────────────────────────┘
//! ```
//!
//! # Trust Model
//!
//! The trust chain for air-gapped verification:
//!
//! 1. **Bundle Verifier Key** (public, provisioned to device at factory)
//! 2. Verifies → **Trust Bundle signature**
//! 3. Bundle contains → **Fulcio root certificates**
//! 4. Anchors → **Certificate chain** in WASM signature
//! 5. Leaf cert contains → **Public key**
//! 6. Verifies → **WASM signature**
//!
//! # Storage Abstraction
//!
//! Like [`TimeSource`](crate::time::TimeSource), storage is abstracted via traits:
//!
//! - [`TrustStore`] - Load trust bundles (from HSM, TPM, flash, or compiled-in)
//! - [`KeyStore`] - Load verifier keys (from secure element, fuses, or files)
//!
//! This allows the same verification code to work across development and production.
//!
//! # Example: Using Storage Traits
//!
//! ```rust,ignore
//! use wsc::airgapped::{
//!     AirGappedVerifier, AirGappedConfig,
//!     CompiledTrustStore, CompiledKeyStore,  // Embedded
//!     FileTrustStore, FileKeyStore,           // Development
//! };
//!
//! // For embedded: compiled into firmware
//! static BUNDLE: &[u8] = include_bytes!("trust-bundle.json");
//! static VERIFIER_KEY: &[u8] = include_bytes!("verifier.pub");
//!
//! let verifier = AirGappedVerifier::from_stores(
//!     &CompiledTrustStore::new(BUNDLE),
//!     &CompiledKeyStore::new(VERIFIER_KEY),
//!     AirGappedConfig::default(),
//! )?;
//!
//! // For development: file-based
//! let verifier = AirGappedVerifier::from_stores(
//!     &FileTrustStore::new("bundle.json"),
//!     &FileKeyStore::new("verifier.pub"),
//!     AirGappedConfig::default(),
//! )?;
//!
//! // For production: implement traits for your HSM/TPM
//! struct HsmKeyStore { slot: u32 }
//! impl KeyStore for HsmKeyStore {
//!     fn load_verifier_key(&self) -> Result<Vec<u8>, WSError> {
//!         hsm_read_public_key(self.slot)
//!     }
//!     fn is_hardware_backed(&self) -> bool { true }
//! }
//! ```
//!
//! # Example: Direct API
//!
//! ```rust,ignore
//! use wsc::airgapped::{AirGappedVerifier, SignedTrustBundle};
//!
//! // Bundle verifier key (compiled into firmware)
//! const BUNDLE_VERIFIER_KEY: &[u8] = include_bytes!("bundle-verifier.pub");
//!
//! // Load signed trust bundle
//! let bundle: SignedTrustBundle = SignedTrustBundle::from_json(&data)?;
//!
//! // Create verifier
//! let verifier = AirGappedVerifier::new(&bundle, BUNDLE_VERIFIER_KEY, config)?;
//!
//! // Verify signature
//! let result = verifier.verify_signature(&keyless_sig, &module_hash)?;
//! ```

mod bundle;
mod config;
mod state;
pub mod storage;
pub mod tuf;
mod verifier;

pub use bundle::*;
pub use config::*;
pub use state::*;
pub use storage::*;
pub use verifier::*;

// Re-export key TUF types
pub use tuf::{fetch_sigstore_trusted_root, parse_trusted_root, trusted_root_to_bundle, SigstoreTrustedRoot, SIGSTORE_TRUSTED_ROOT_URL};
