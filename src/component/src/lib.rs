//! WebAssembly component that exports the wsc signing interface
//!
//! This component wraps the wsc library and exports a clean WIT interface
//! for key generation, signing, and verification operations.

#[cfg(target_arch = "wasm32")]
use signing_lib_bindings::exports::wasm_signatures::wasmsign::signing::{
    Guest, KeyPair, SignOptions, SignResult,
};

#[cfg(target_arch = "wasm32")]
use std::io::Cursor;
#[cfg(target_arch = "wasm32")]
use wsc::{KeyPair as WS2KeyPair, Module, PublicKey, SecretKey};

// Export the component implementation
#[cfg(target_arch = "wasm32")]
struct Component;

#[cfg(target_arch = "wasm32")]
impl Guest for Component {
    fn keygen() -> Result<KeyPair, String> {
        // Generate a new key pair using wsc library
        let kp = WS2KeyPair::generate();

        Ok(KeyPair {
            public_key: kp.pk.to_bytes(),
            secret_key: kp.sk.to_bytes(),
        })
    }

    fn sign(
        module_bytes: Vec<u8>,
        secret_key: Vec<u8>,
        public_key: Option<Vec<u8>>,
        options: SignOptions,
    ) -> Result<SignResult, String> {
        // Parse the secret key
        let sk =
            SecretKey::from_bytes(&secret_key).map_err(|e| format!("Invalid secret key: {}", e))?;

        // Parse the module
        let mut module_reader = Cursor::new(&module_bytes);
        let module = Module::deserialize(&mut module_reader)
            .map_err(|e| format!("Invalid WASM module: {}", e))?;

        // Determine key ID if public key provided
        let key_id = if let Some(pk_bytes) = public_key {
            let pk = PublicKey::from_bytes(&pk_bytes)
                .map_err(|e| format!("Invalid public key: {}", e))?;
            pk.key_id.clone()
        } else {
            options.key_id
        };

        // Sign the module (always embeds signature first)
        let signed_module = sk
            .sign(module, key_id.as_ref())
            .map_err(|e| format!("Signing failed: {}", e))?;

        if options.detached {
            // Detach the signature
            let (_unsigned_module, sig_bytes) = signed_module
                .detach_signature()
                .map_err(|e| format!("Failed to detach signature: {}", e))?;

            // Return the detached signature bytes
            Ok(SignResult::Detached(sig_bytes))
        } else {
            // Return the signed module with embedded signature
            let mut output = Vec::new();
            signed_module
                .serialize(&mut output)
                .map_err(|e| format!("Serialization failed: {}", e))?;
            Ok(SignResult::Embedded(output))
        }
    }

    fn verify(
        module_bytes: Vec<u8>,
        public_key: Vec<u8>,
        detached_sig: Option<Vec<u8>>,
    ) -> Result<bool, String> {
        // Parse the public key
        let pk =
            PublicKey::from_bytes(&public_key).map_err(|e| format!("Invalid public key: {}", e))?;

        // Create a reader over the module bytes
        let mut reader = Cursor::new(&module_bytes);

        // Verify based on signature type
        match pk.verify(&mut reader, detached_sig.as_deref()) {
            Ok(()) => Ok(true),
            Err(wsc::WSError::NoSignatures) => Ok(false),
            Err(wsc::WSError::VerificationFailed) => Ok(false),
            Err(e) => Err(format!("Verification error: {}", e)),
        }
    }

    fn parse_public_key(key_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
        // Try to parse as any supported format
        let pk = PublicKey::from_any(&key_bytes)
            .map_err(|e| format!("Failed to parse public key: {}", e))?;

        Ok(pk.to_bytes())
    }

    fn parse_secret_key(key_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
        // Try to parse as any supported format
        // Try raw bytes first
        if let Ok(sk) = SecretKey::from_bytes(&key_bytes) {
            return Ok(sk.to_bytes());
        }
        // Try DER
        if let Ok(sk) = SecretKey::from_der(&key_bytes) {
            return Ok(sk.to_bytes());
        }
        // Try PEM/OpenSSH
        if let Ok(s) = std::str::from_utf8(&key_bytes) {
            if let Ok(sk) = SecretKey::from_pem(s) {
                return Ok(sk.to_bytes());
            }
            if let Ok(sk) = SecretKey::from_openssh(s) {
                return Ok(sk.to_bytes());
            }
        }
        Err("Failed to parse secret key in any known format".to_string())
    }

    fn to_pem_public(key_bytes: Vec<u8>) -> Result<String, String> {
        let pk =
            PublicKey::from_bytes(&key_bytes).map_err(|e| format!("Invalid public key: {}", e))?;

        Ok(pk.to_pem())
    }

    fn to_pem_secret(key_bytes: Vec<u8>) -> Result<String, String> {
        let sk =
            SecretKey::from_bytes(&key_bytes).map_err(|e| format!("Invalid secret key: {}", e))?;

        Ok(sk.to_pem())
    }
}

#[cfg(target_arch = "wasm32")]
signing_lib_bindings::export!(Component with_types_in signing_lib_bindings);
