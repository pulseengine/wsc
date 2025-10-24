use crate::signature::*;
use crate::wasm_module::*;
use crate::*;

use log::*;
use std::collections::{HashMap, HashSet};
use std::io::Read;

impl SecretKey {
    /// Sign a module with the secret key.
    ///
    /// If the module was already signed, the signature is replaced.
    ///
    /// `key_id` is the key identifier of the public key, to be stored with the signature.
    /// This parameter is optional.
    pub fn sign(&self, mut module: Module, key_id: Option<&Vec<u8>>) -> Result<Module, WSError> {
        let mut out_sections = vec![Section::Custom(CustomSection::default())];
        let mut hasher = Hash::new();
        for section in module.sections.into_iter() {
            if section.is_signature_header() {
                continue;
            }
            section.serialize(&mut hasher)?;
            out_sections.push(section);
        }
        let h = hasher.finalize().to_vec();

        let mut msg: Vec<u8> = vec![];
        msg.extend_from_slice(SIGNATURE_WASM_DOMAIN.as_bytes());
        msg.extend_from_slice(&[
            SIGNATURE_VERSION,
            SIGNATURE_WASM_MODULE_CONTENT_TYPE,
            SIGNATURE_HASH_FUNCTION,
        ]);
        msg.extend_from_slice(&h);

        let signature = self.sk.sign(msg, None).to_vec();

        let signature_for_hashes = SignatureForHashes {
            key_id: key_id.cloned(),
            alg_id: ED25519_PK_ID,
            signature,
        };
        let signed_hashes_set = vec![SignedHashes {
            hashes: vec![h],
            signatures: vec![signature_for_hashes],
        }];
        let signature_data = SignatureData {
            specification_version: SIGNATURE_VERSION,
            content_type: SIGNATURE_WASM_MODULE_CONTENT_TYPE,
            hash_function: SIGNATURE_HASH_FUNCTION,
            signed_hashes_set,
        };
        out_sections[0] = Section::Custom(CustomSection::new(
            SIGNATURE_SECTION_HEADER_NAME.to_string(),
            signature_data.serialize()?,
        ));

        module.sections = out_sections;
        Ok(module)
    }
}

impl PublicKey {
    /// Verify a module's signature.
    ///
    /// `reader` is a reader over the raw module data.
    ///
    /// `detached_signature` allows the caller to verify a module without an embedded signature.
    ///
    /// This simplified interface verifies the entire module, with a single public key.
    pub fn verify(
        &self,
        reader: &mut impl Read,
        detached_signature: Option<&[u8]>,
    ) -> Result<(), WSError> {
        let stream = Module::init_from_reader(reader)?;
        let mut sections = Module::iterate(stream)?;

        // Read the signature header from the module, or reconstruct it from the detached signature.
        let signature_header_section = if let Some(detached_signature) = &detached_signature {
            Section::Custom(CustomSection::new(
                SIGNATURE_SECTION_HEADER_NAME.to_string(),
                detached_signature.to_vec(),
            ))
        } else {
            sections.next().ok_or(WSError::ParseError)??
        };
        let signature_header = match signature_header_section {
            Section::Custom(custom_section) if custom_section.is_signature_header() => {
                custom_section
            }
            _ => {
                debug!("This module is not signed");
                return Err(WSError::NoSignatures);
            }
        };

        // Actual signature verification starts here.
        let signature_data = signature_header.signature_data()?;
        if signature_data.hash_function != SIGNATURE_HASH_FUNCTION {
            debug!(
                "Unsupported hash function: {:02x}",
                signature_data.specification_version
            );
            return Err(WSError::ParseError);
        }

        let signed_hashes_set = signature_data.signed_hashes_set;
        let valid_hashes = self.valid_hashes_for_pk(&signed_hashes_set)?;
        if valid_hashes.is_empty() {
            debug!("No valid signatures");
            return Err(WSError::VerificationFailed);
        }

        let mut hasher = Hash::new();
        let mut buf = vec![0u8; 65536];
        loop {
            match reader.read(&mut buf)? {
                0 => break,
                n => {
                    hasher.update(&buf[..n]);
                }
            }
        }
        let h = hasher.finalize().to_vec();

        if valid_hashes.contains(&h) {
            Ok(())
        } else {
            Err(WSError::VerificationFailed)
        }
    }
}

impl PublicKeySet {
    /// Verify a module's signature with multiple public keys.
    ///
    /// `reader` is a reader over the raw module data.
    ///
    /// `detached_signature` allows the caller to verify a module without an embedded signature.
    ///
    /// This simplified interface verifies the entire module, with all public keys from the set.
    /// It returns the set of public keys for which a valid signature was found.
    pub fn verify(
        &self,
        reader: &mut impl Read,
        detached_signature: Option<&[u8]>,
    ) -> Result<HashSet<&PublicKey>, WSError> {
        let mut sections = Module::iterate(Module::init_from_reader(reader)?)?;

        // Read the signature header from the module, or reconstruct it from the detached signature.
        let signature_header: &Section;
        let signature_header_from_detached_signature;
        let signature_header_from_stream;
        if let Some(detached_signature) = &detached_signature {
            signature_header_from_detached_signature = Section::Custom(CustomSection::new(
                SIGNATURE_SECTION_HEADER_NAME.to_string(),
                detached_signature.to_vec(),
            ));
            signature_header = &signature_header_from_detached_signature;
        } else {
            signature_header_from_stream = sections.next().ok_or(WSError::ParseError)??;
            signature_header = &signature_header_from_stream;
        }
        let signature_header = match signature_header {
            Section::Custom(custom_section) if custom_section.is_signature_header() => {
                custom_section
            }
            _ => {
                debug!("This module is not signed");
                return Err(WSError::NoSignatures);
            }
        };

        // Actual signature verification starts here.
        let signature_data = signature_header.signature_data()?;
        if signature_data.content_type != SIGNATURE_WASM_MODULE_CONTENT_TYPE {
            debug!(
                "Unsupported content type: {:02x}",
                signature_data.content_type
            );
            return Err(WSError::ParseError);
        }
        if signature_data.hash_function != SIGNATURE_HASH_FUNCTION {
            debug!(
                "Unsupported hash function: {:02x}",
                signature_data.specification_version
            );
            return Err(WSError::ParseError);
        }
        let signed_hashes_set = signature_data.signed_hashes_set;
        let valid_hashes_for_pks: HashMap<&PublicKey, HashSet<&Vec<u8>>> = self
            .pks
            .iter()
            .filter_map(|pk| match pk.valid_hashes_for_pk(&signed_hashes_set) {
                Ok(valid_hashes) if !valid_hashes.is_empty() => Some((pk, valid_hashes)),
                _ => None,
            })
            .collect();
        if valid_hashes_for_pks.is_empty() {
            debug!("No valid signatures");
            return Err(WSError::VerificationFailed);
        }

        let mut hasher = Hash::new();
        let mut buf = vec![0u8; 65536];
        loop {
            match reader.read(&mut buf)? {
                0 => break,
                n => {
                    hasher.update(&buf[..n]);
                }
            }
        }
        let h = hasher.finalize().to_vec();
        let mut valid_pks = HashSet::new();
        for (pk, valid_hashes) in valid_hashes_for_pks {
            if valid_hashes.contains(&h) {
                valid_pks.insert(pk);
            }
        }
        if valid_pks.is_empty() {
            debug!("No valid signatures");
            return Err(WSError::VerificationFailed);
        }
        Ok(valid_pks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn create_test_module() -> Module {
        Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Function, vec![4, 5, 6])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        }
    }

    fn serialize_module(module: &Module) -> Vec<u8> {
        let mut buffer = Vec::new();
        module.serialize(&mut buffer).unwrap();
        buffer
    }

    #[test]
    fn test_sign_module() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        let signed_module = kp.sk.sign(module, None).unwrap();

        // First section should be signature
        assert!(signed_module.sections[0].is_signature_header());
    }

    #[test]
    fn test_sign_module_with_key_id() {
        let kp = KeyPair::generate();
        let module = create_test_module();
        let key_id = vec![1, 2, 3, 4];

        let signed_module = kp.sk.sign(module, Some(&key_id)).unwrap();

        // Verify signature header exists
        assert!(signed_module.sections[0].is_signature_header());
    }

    #[test]
    fn test_sign_replaces_existing_signature() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        // Sign once
        let signed_module = kp.sk.sign(module, None).unwrap();

        // Sign again - should replace signature
        let signed_module2 = kp.sk.sign(signed_module, None).unwrap();

        // Should still have only one signature header
        let sig_headers: Vec<_> = signed_module2
            .sections
            .iter()
            .filter(|s| s.is_signature_header())
            .collect();
        assert_eq!(sig_headers.len(), 1);
    }

    #[test]
    fn test_verify_signed_module() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        let signed_module = kp.sk.sign(module, None).unwrap();
        let signed_bytes = serialize_module(&signed_module);

        let mut reader = Cursor::new(signed_bytes);
        let result = kp.pk.verify(&mut reader, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_unsigned_module() {
        let kp = KeyPair::generate();
        let module = create_test_module();
        let unsigned_bytes = serialize_module(&module);

        let mut reader = Cursor::new(unsigned_bytes);
        let result = kp.pk.verify(&mut reader, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::NoSignatures));
    }

    #[test]
    fn test_verify_with_wrong_key() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let module = create_test_module();

        // Sign with key 1
        let signed_module = kp1.sk.sign(module, None).unwrap();
        let signed_bytes = serialize_module(&signed_module);

        // Try to verify with key 2
        let mut reader = Cursor::new(signed_bytes);
        let result = kp2.pk.verify(&mut reader, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::VerificationFailed));
    }

    #[test]
    fn test_verify_with_detached_signature() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        // Sign and detach
        let signed_module = kp.sk.sign(module, None).unwrap();
        let (unsigned_module, detached_sig) = signed_module.detach_signature().unwrap();
        let unsigned_bytes = serialize_module(&unsigned_module);

        // Verify with detached signature
        let mut reader = Cursor::new(unsigned_bytes);
        let result = kp.pk.verify(&mut reader, Some(&detached_sig));
        assert!(result.is_ok());
    }

    #[test]
    fn test_public_key_set_verify() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let module = create_test_module();

        // Sign with key 1
        let signed_module = kp1.sk.sign(module, None).unwrap();
        let signed_bytes = serialize_module(&signed_module);

        // Create a key set with both keys
        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp1.pk.clone()).unwrap();
        key_set.insert(kp2.pk).unwrap();

        // Verify - should find key 1
        let mut reader = Cursor::new(signed_bytes);
        let result = key_set.verify(&mut reader, None);
        assert!(result.is_ok());
        let valid_pks = result.unwrap();
        assert_eq!(valid_pks.len(), 1);
        assert!(valid_pks.contains(&kp1.pk));
    }

    #[test]
    fn test_public_key_set_verify_unsigned() {
        let kp = KeyPair::generate();
        let module = create_test_module();
        let unsigned_bytes = serialize_module(&module);

        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp.pk).unwrap();

        let mut reader = Cursor::new(unsigned_bytes);
        let result = key_set.verify(&mut reader, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::NoSignatures));
    }

    #[test]
    fn test_public_key_set_verify_no_matching_keys() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let module = create_test_module();

        // Sign with key 1
        let signed_module = kp1.sk.sign(module, None).unwrap();
        let signed_bytes = serialize_module(&signed_module);

        // Create key set with only key 2 (different)
        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp2.pk).unwrap();

        let mut reader = Cursor::new(signed_bytes);
        let result = key_set.verify(&mut reader, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::VerificationFailed));
    }

    #[test]
    fn test_public_key_set_verify_with_detached_signature() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        // Sign and detach
        let signed_module = kp.sk.sign(module, None).unwrap();
        let (unsigned_module, detached_sig) = signed_module.detach_signature().unwrap();
        let unsigned_bytes = serialize_module(&unsigned_module);

        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp.pk.clone()).unwrap();

        // Verify with detached signature
        let mut reader = Cursor::new(unsigned_bytes);
        let result = key_set.verify(&mut reader, Some(&detached_sig));
        assert!(result.is_ok());
        let valid_pks = result.unwrap();
        assert_eq!(valid_pks.len(), 1);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        // Sign
        let signed_module = kp.sk.sign(module, None).unwrap();

        // Serialize
        let signed_bytes = serialize_module(&signed_module);

        // Verify
        let mut reader = Cursor::new(signed_bytes);
        let result = kp.pk.verify(&mut reader, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_with_modified_module_fails() {
        let kp = KeyPair::generate();
        let module = create_test_module();

        // Sign
        let signed_module = kp.sk.sign(module, None).unwrap();
        let mut signed_bytes = serialize_module(&signed_module);

        // Modify the signed bytes (corrupt the module)
        if signed_bytes.len() > 50 {
            signed_bytes[50] ^= 0xFF;
        }

        // Verify should fail
        let mut reader = Cursor::new(signed_bytes);
        let result = kp.pk.verify(&mut reader, None);
        assert!(result.is_err());
    }
}
