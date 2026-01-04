//! Signature information extraction.
//!
//! This module provides utilities for querying signature metadata from
//! WebAssembly modules without performing full verification.
//!
//! Backported from wasmsign2 (commit 8223bec, 2025-12-18).

use crate::error::*;
use crate::signature::sig_sections::{SignatureData, SIGNATURE_SECTION_HEADER_NAME};
use crate::wasm_module::{Module, Section};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Information about signatures in a WebAssembly module.
///
/// This struct provides easy access to signature metadata without
/// performing cryptographic verification.
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    key_ids: Vec<Vec<u8>>,
    signature_count: usize,
    /// The specification version of the signature format.
    pub specification_version: u8,
    /// The content type (0x01 for WebAssembly modules).
    pub content_type: u8,
    /// The hash function used (0x01 for SHA-256).
    pub hash_function: u8,
}

impl SignatureInfo {
    fn from_signature_data(data: &SignatureData) -> Self {
        let mut key_ids = Vec::new();
        let mut signature_count = 0;

        for signed_hashes in &data.signed_hashes_set {
            for sig in &signed_hashes.signatures {
                if let Some(key_id) = &sig.key_id {
                    key_ids.push(key_id.clone());
                }
                signature_count += 1;
            }
        }

        SignatureInfo {
            key_ids,
            signature_count,
            specification_version: data.specification_version,
            content_type: data.content_type,
            hash_function: data.hash_function,
        }
    }

    /// Returns the key IDs from signatures that have them.
    ///
    /// Signatures created without key IDs are not included. To detect
    /// anonymous signatures, compare `key_ids().len()` with `signature_count()`.
    pub fn key_ids(&self) -> &[Vec<u8>] {
        &self.key_ids
    }

    /// Returns the total number of signatures (with or without key IDs).
    pub fn signature_count(&self) -> usize {
        self.signature_count
    }

    /// Returns true if the module has at least one signature.
    pub fn is_signed(&self) -> bool {
        self.signature_count > 0
    }
}

impl Module {
    /// Get signature information from this module.
    ///
    /// Returns `SignatureInfo` containing key IDs and other signature metadata.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let module = Module::deserialize_from_file("signed.wasm")?;
    /// let info = module.signature_info()?;
    /// for key_id in info.key_ids() {
    ///     println!("Key ID: {:02x?}", key_id);
    /// }
    /// ```
    pub fn signature_info(&self) -> Result<SignatureInfo, WSError> {
        for section in &self.sections {
            if let Section::Custom(custom) = section {
                if custom.is_signature_header() {
                    let data = custom.signature_data()?;
                    return Ok(SignatureInfo::from_signature_data(&data));
                }
            }
        }
        Err(WSError::NoSignatures)
    }
}

/// Get signature information from a WebAssembly module file.
///
/// This is a convenience function that opens and parses a file to extract
/// signature information without loading the entire module into memory.
///
/// # Example
///
/// ```ignore
/// let info = wsc::signature_info_from_file("signed.wasm")?;
/// println!("Module has {} signatures", info.signature_count());
/// for key_id in info.key_ids() {
///     println!("Key ID: {:02x?}", key_id);
/// }
/// ```
pub fn signature_info_from_file(path: impl AsRef<Path>) -> Result<SignatureInfo, WSError> {
    let fp = File::open(path.as_ref())?;
    signature_info_from_reader(&mut BufReader::new(fp), None)
}

/// Get signature information from a reader in streaming fashion.
///
/// This function reads only the signature section without loading the entire
/// module, making it efficient for large modules.
///
/// `detached_signature` allows reading signature info from a detached signature
/// instead of an embedded one.
///
/// # Example
///
/// ```ignore
/// let mut file = File::open("signed.wasm")?;
/// let info = wsc::signature_info_from_reader(&mut file, None)?;
/// println!("Found {} key IDs", info.key_ids().len());
/// ```
pub fn signature_info_from_reader(
    reader: &mut impl Read,
    detached_signature: Option<&[u8]>,
) -> Result<SignatureInfo, WSError> {
    if let Some(detached) = detached_signature {
        let data = SignatureData::deserialize(detached)?;
        return Ok(SignatureInfo::from_signature_data(&data));
    }

    let stream = Module::init_from_reader(reader)?;
    let mut sections = Module::iterate(stream)?;

    let first_section = sections.next().ok_or(WSError::ParseError)??;

    match first_section {
        Section::Custom(custom) if custom.name() == SIGNATURE_SECTION_HEADER_NAME => {
            let data = custom.signature_data()?;
            Ok(SignatureInfo::from_signature_data(&data))
        }
        _ => Err(WSError::NoSignatures),
    }
}

/// Get signature information from a detached signature.
///
/// This function parses a detached signature blob directly without needing
/// access to the original module.
///
/// # Example
///
/// ```ignore
/// let signature_bytes = std::fs::read("signature.bin")?;
/// let info = wsc::signature_info_from_detached(&signature_bytes)?;
/// println!("Detached signature has {} keys", info.key_ids().len());
/// ```
pub fn signature_info_from_detached(detached_signature: &[u8]) -> Result<SignatureInfo, WSError> {
    let data = SignatureData::deserialize(detached_signature)?;
    Ok(SignatureInfo::from_signature_data(&data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;
    use std::io::Cursor;

    fn create_test_module() -> Module {
        Module {
            header: [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00],
            sections: vec![],
        }
    }

    #[test]
    fn test_signature_info_from_signed_module() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        let (signed_module, _) = kp
            .sk
            .sign_multi(module, None, false, false)
            .expect("Failed to sign");

        let info = signed_module
            .signature_info()
            .expect("Failed to get signature info");

        assert!(info.is_signed());
        assert_eq!(info.signature_count(), 1);
        assert_eq!(info.specification_version, 0x01);
        assert_eq!(info.content_type, 0x01);
        assert_eq!(info.hash_function, 0x01);
    }

    #[test]
    fn test_signature_info_with_key_id() {
        let kp = KeyPair::generate();
        let pk_with_id = kp.pk.clone().attach_default_key_id();
        let key_id = pk_with_id.key_id().expect("Should have key ID");

        let module = create_test_module();

        let (signed_module, _) = kp
            .sk
            .sign_multi(module, Some(&key_id), false, false)
            .expect("Failed to sign");

        let info = signed_module
            .signature_info()
            .expect("Failed to get signature info");

        assert_eq!(info.key_ids().len(), 1);
        assert_eq!(&info.key_ids()[0], key_id);
    }

    #[test]
    fn test_signature_info_unsigned_module() {
        let module = create_test_module();

        let result = module.signature_info();
        assert!(matches!(result, Err(WSError::NoSignatures)));
    }

    #[test]
    fn test_signature_info_from_reader() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        let (signed_module, _) = kp
            .sk
            .sign_multi(module, None, false, false)
            .expect("Failed to sign");

        let mut bytes = Vec::new();
        signed_module
            .serialize(&mut bytes)
            .expect("Failed to serialize");

        let info = signature_info_from_reader(&mut Cursor::new(&bytes), None)
            .expect("Failed to get signature info");

        assert!(info.is_signed());
        assert_eq!(info.signature_count(), 1);
    }

    #[test]
    fn test_signature_info_from_detached() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        let (_, detached_sig) = kp
            .sk
            .sign_multi(module, None, true, false)
            .expect("Failed to sign");

        let info =
            signature_info_from_detached(&detached_sig).expect("Failed to get signature info");

        assert!(info.is_signed());
        assert_eq!(info.signature_count(), 1);
    }

    #[test]
    fn test_multiple_signatures_info() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let module = create_test_module();

        let (signed_once, _) = kp1
            .sk
            .sign_multi(module, None, false, false)
            .expect("Failed to sign");

        let (signed_twice, _) = kp2
            .sk
            .sign_multi(signed_once, None, false, false)
            .expect("Failed to sign");

        let info = signed_twice
            .signature_info()
            .expect("Failed to get signature info");

        assert!(info.is_signed());
        assert_eq!(info.signature_count(), 2);
    }
}
