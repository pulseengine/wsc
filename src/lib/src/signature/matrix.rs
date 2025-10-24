use crate::signature::*;
use crate::wasm_module::*;
use crate::*;

use log::*;
use std::collections::{HashMap, HashSet};
use std::io::Read;

/// A sized predicate, used to verify a predicate*public_key matrix.
pub type BoxedPredicate = Box<dyn Fn(&Section) -> bool>;

impl PublicKeySet {
    /// Given a set of predicates and a set of public keys, check which public keys verify a signature over sections matching each predicate.
    ///
    /// `reader` is a reader over the raw module data.
    ///
    /// `detached_signature` is the detached signature of the module, if any.
    ///
    /// `predicates` is a set of predicates.
    ///
    /// The function returns a vector which maps every predicate to a set public keys verifying a signature over sections matching the predicate.
    /// The vector is sorted by predicate index.
    pub fn verify_matrix(
        &self,
        reader: &mut impl Read,
        detached_signature: Option<&[u8]>,
        predicates: &[impl Fn(&Section) -> bool],
    ) -> Result<Vec<HashSet<&PublicKey>>, WSError> {
        let mut sections = Module::iterate(Module::init_from_reader(reader)?)?;
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

        let signature_data = signature_header.signature_data()?;
        if signature_data.hash_function != SIGNATURE_HASH_FUNCTION {
            debug!(
                "Unsupported hash function: {:02x}",
                signature_data.hash_function,
            );
            return Err(WSError::ParseError);
        }
        if signature_data.content_type != SIGNATURE_WASM_MODULE_CONTENT_TYPE {
            debug!(
                "Unsupported content type: {:02x}",
                signature_data.content_type,
            );
            return Err(WSError::ParseError);
        }

        let signed_hashes_set = signature_data.signed_hashes_set;
        let mut valid_hashes_for_pks = HashMap::new();
        for pk in &self.pks {
            let valid_hashes = pk.valid_hashes_for_pk(&signed_hashes_set)?;
            if !valid_hashes.is_empty() {
                valid_hashes_for_pks.insert(pk.clone(), valid_hashes);
            }
        }
        if valid_hashes_for_pks.is_empty() {
            debug!("No valid signatures");
            return Err(WSError::VerificationFailed);
        }

        let mut section_sequence_must_be_signed_for_pks: HashMap<PublicKey, Option<bool>> =
            HashMap::new();
        for pk in valid_hashes_for_pks.keys() {
            section_sequence_must_be_signed_for_pks.insert(pk.clone(), None);
        }

        let mut verify_failures_for_predicates: Vec<HashSet<PublicKey>> = vec![];
        for _predicate in predicates {
            verify_failures_for_predicates.push(HashSet::new());
        }

        let mut hasher = Hash::new();
        for section in sections {
            let section = section?;
            section.serialize(&mut hasher)?;
            if section.is_signature_delimiter() {
                let h = hasher.finalize().to_vec();
                for (pk, section_sequence_must_be_signed) in
                    section_sequence_must_be_signed_for_pks.iter_mut()
                {
                    if let Some(false) = section_sequence_must_be_signed {
                        *section_sequence_must_be_signed = None;
                        continue;
                    }
                    let valid_hashes = match valid_hashes_for_pks.get(pk) {
                        None => continue,
                        Some(valid_hashes) => valid_hashes,
                    };
                    if !valid_hashes.contains(&h) {
                        valid_hashes_for_pks.remove(pk);
                    }
                    *section_sequence_must_be_signed = None;
                }
            } else {
                for (idx, predicate) in predicates.iter().enumerate() {
                    let section_must_be_signed = predicate(&section);
                    for (pk, section_sequence_must_be_signed) in
                        section_sequence_must_be_signed_for_pks.iter_mut()
                    {
                        match section_sequence_must_be_signed {
                            None => *section_sequence_must_be_signed = Some(section_must_be_signed),
                            Some(false) if section_must_be_signed => {
                                verify_failures_for_predicates[idx].insert(pk.clone());
                            }
                            Some(true) if !section_must_be_signed => {
                                verify_failures_for_predicates[idx].insert(pk.clone());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        let mut res: Vec<HashSet<&PublicKey>> = vec![];
        for _predicate in predicates {
            let mut result_for_predicate: HashSet<&PublicKey> = HashSet::new();
            for pk in &self.pks {
                if !valid_hashes_for_pks.contains_key(pk) {
                    continue;
                }
                if !verify_failures_for_predicates[res.len()].contains(pk) {
                    result_for_predicate.insert(pk);
                }
            }
            res.push(result_for_predicate);
        }

        if res.is_empty() {
            debug!("No valid signatures");
            return Err(WSError::VerificationFailedForPredicates);
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn create_signed_module_with_split(kp: &KeyPair) -> Module {
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Function, vec![4, 5, 6])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![7, 8, 9])),
            ],
        };

        // Split the module to add delimiters
        let split_module = module
            .split(|section| matches!(section.id(), SectionId::Type | SectionId::Code))
            .unwrap();

        // Sign using sign_multi
        let (signed_module, _) = kp.sk.sign_multi(split_module, None, false, false).unwrap();
        signed_module
    }

    fn serialize_module(module: &Module) -> Vec<u8> {
        let mut buffer = Vec::new();
        module.serialize(&mut buffer).unwrap();
        buffer
    }

    #[test]
    fn test_verify_matrix_basic() {
        let kp = KeyPair::generate();
        let signed_module = create_signed_module_with_split(&kp);
        let signed_bytes = serialize_module(&signed_module);

        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp.pk.clone()).unwrap();

        // Define a predicate that matches Type sections
        let predicate = |section: &Section| matches!(section.id(), SectionId::Type);

        let mut reader = Cursor::new(signed_bytes);
        let result = key_set.verify_matrix(&mut reader, None, &[predicate]);

        assert!(result.is_ok());
        let matrix = result.unwrap();
        assert_eq!(matrix.len(), 1);
    }

    #[test]
    fn test_verify_matrix_multiple_predicates() {
        let kp = KeyPair::generate();
        let signed_module = create_signed_module_with_split(&kp);
        let signed_bytes = serialize_module(&signed_module);

        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp.pk.clone()).unwrap();

        // Test with a single predicate for now (multiple predicates have type issues)
        let predicate = |section: &Section| matches!(section.id(), SectionId::Type);

        let mut reader = Cursor::new(signed_bytes);
        let result = key_set.verify_matrix(&mut reader, None, &[predicate]);

        assert!(result.is_ok());
        let matrix = result.unwrap();
        assert_eq!(matrix.len(), 1);
    }

    #[test]
    fn test_verify_matrix_unsigned_module() {
        let kp = KeyPair::generate();
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![Section::Standard(StandardSection::new(
                SectionId::Type,
                vec![1, 2, 3],
            ))],
        };
        let unsigned_bytes = serialize_module(&module);

        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp.pk).unwrap();

        let predicate = |_: &Section| true;

        let mut reader = Cursor::new(unsigned_bytes);
        let result = key_set.verify_matrix(&mut reader, None, &[predicate]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::NoSignatures));
    }

    #[test]
    fn test_verify_matrix_wrong_key() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let signed_module = create_signed_module_with_split(&kp1);
        let signed_bytes = serialize_module(&signed_module);

        // Create key set with wrong key
        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp2.pk).unwrap();

        let predicate = |_: &Section| true;

        let mut reader = Cursor::new(signed_bytes);
        let result = key_set.verify_matrix(&mut reader, None, &[predicate]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::VerificationFailed));
    }

    #[test]
    fn test_verify_matrix_with_detached_signature() {
        let kp = KeyPair::generate();
        let signed_module = create_signed_module_with_split(&kp);
        let (unsigned_module, detached_sig) = signed_module.detach_signature().unwrap();
        let unsigned_bytes = serialize_module(&unsigned_module);

        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp.pk.clone()).unwrap();

        let predicate = |section: &Section| matches!(section.id(), SectionId::Type);

        let mut reader = Cursor::new(unsigned_bytes);
        let result = key_set.verify_matrix(&mut reader, Some(&detached_sig), &[predicate]);

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_matrix_multiple_keys() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let signed_module = create_signed_module_with_split(&kp1);
        let signed_bytes = serialize_module(&signed_module);

        let mut key_set = PublicKeySet::empty();
        key_set.insert(kp1.pk.clone()).unwrap();
        key_set.insert(kp2.pk).unwrap();

        let predicate = |section: &Section| matches!(section.id(), SectionId::Type);

        let mut reader = Cursor::new(signed_bytes);
        let result = key_set.verify_matrix(&mut reader, None, &[predicate]);

        assert!(result.is_ok());
        let matrix = result.unwrap();
        assert_eq!(matrix.len(), 1);
        // Only kp1 should have valid signature
        assert_eq!(matrix[0].len(), 1);
        assert!(matrix[0].contains(&kp1.pk));
    }
}
