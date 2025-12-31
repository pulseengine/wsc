use log::*;
use std::io::{BufReader, BufWriter, prelude::*};

use crate::ED25519_PK_ID;
use crate::SIGNATURE_VERSION;
use crate::SIGNATURE_WASM_MODULE_CONTENT_TYPE;
use crate::error::*;
use crate::wasm_module::*;

pub const SIGNATURE_SECTION_HEADER_NAME: &str = "signature";
pub const SIGNATURE_SECTION_DELIMITER_NAME: &str = "signature_delimiter";

pub const MAX_HASHES: usize = 64;
pub const MAX_SIGNATURES: usize = 256;

#[derive(PartialEq, Debug, Clone, Eq)]
pub struct SignatureForHashes {
    pub key_id: Option<Vec<u8>>,
    pub alg_id: u8,
    pub signature: Vec<u8>,
    /// Certificate chain for certificate-based signing
    /// Format: [device_cert_der, intermediate_cert_der, ...]
    /// Device certificate comes first, root certificate last (optional)
    pub certificate_chain: Option<Vec<Vec<u8>>>,
}

#[derive(PartialEq, Debug, Clone, Eq)]
pub struct SignedHashes {
    pub hashes: Vec<Vec<u8>>,
    pub signatures: Vec<SignatureForHashes>,
}

#[derive(PartialEq, Debug, Clone, Eq)]
pub struct SignatureData {
    pub specification_version: u8,
    pub content_type: u8,
    pub hash_function: u8,
    pub signed_hashes_set: Vec<SignedHashes>,
}

impl SignatureForHashes {
    pub fn serialize(&self) -> Result<Vec<u8>, WSError> {
        let mut writer = BufWriter::new(Vec::new());
        if let Some(key_id) = &self.key_id {
            varint::put_slice(&mut writer, key_id)?;
        } else {
            varint::put(&mut writer, 0)?;
        }
        writer.write_all(&[self.alg_id])?;
        varint::put_slice(&mut writer, &self.signature)?;

        // Serialize certificate chain (optional, for backward compatibility)
        if let Some(cert_chain) = &self.certificate_chain {
            varint::put(&mut writer, cert_chain.len() as _)?;
            for cert in cert_chain {
                varint::put_slice(&mut writer, cert)?;
            }
        } else {
            varint::put(&mut writer, 0)?; // No certificate chain
        }

        writer
            .into_inner()
            .map_err(|e| WSError::IOError(std::io::Error::other(format!("buffer flush failed: {}", e))))
    }

    pub fn deserialize(bin: impl AsRef<[u8]>) -> Result<Self, WSError> {
        let mut reader = BufReader::new(bin.as_ref());
        let key_id = varint::get_slice(&mut reader)?;
        let key_id = if key_id.is_empty() {
            None
        } else {
            Some(key_id)
        };
        let mut alg_id = [0u8; 1];
        reader.read_exact(&mut alg_id)?;
        let alg_id = alg_id[0];
        if alg_id != ED25519_PK_ID {
            debug!("Unsupported algorithm: {:02x}", alg_id);
            return Err(WSError::ParseError);
        }
        let signature = varint::get_slice(&mut reader)?;

        // Deserialize certificate chain (optional, for backward compatibility)
        let certificate_chain = if let Ok(cert_count) = varint::get32(&mut reader) {
            if cert_count > 0 {
                let mut certs = Vec::with_capacity(cert_count as usize);
                for _ in 0..cert_count {
                    if let Ok(cert) = varint::get_slice(&mut reader) {
                        certs.push(cert);
                    }
                }
                Some(certs)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            key_id,
            alg_id,
            signature,
            certificate_chain,
        })
    }
}

impl SignedHashes {
    pub fn serialize(&self) -> Result<Vec<u8>, WSError> {
        let mut writer = BufWriter::new(Vec::new());
        varint::put(&mut writer, self.hashes.len() as _)?;
        for hash in &self.hashes {
            writer.write_all(hash)?;
        }
        varint::put(&mut writer, self.signatures.len() as _)?;
        for signature in &self.signatures {
            varint::put_slice(&mut writer, &signature.serialize()?)?;
        }
        writer
            .into_inner()
            .map_err(|e| WSError::IOError(std::io::Error::other(format!("buffer flush failed: {}", e))))
    }

    pub fn deserialize(bin: impl AsRef<[u8]>) -> Result<Self, WSError> {
        let mut reader = BufReader::new(bin.as_ref());
        let hashes_count = varint::get32(&mut reader)? as _;
        if hashes_count > MAX_HASHES {
            debug!("Too many hashes: {} (max: {})", hashes_count, MAX_HASHES);
            return Err(WSError::TooManyHashes(MAX_HASHES));
        }
        let mut hashes = Vec::with_capacity(hashes_count);
        for _ in 0..hashes_count {
            let mut hash = vec![0; 32];
            reader.read_exact(&mut hash)?;
            hashes.push(hash);
        }
        let signatures_count = varint::get32(&mut reader)? as _;
        if signatures_count > MAX_SIGNATURES {
            debug!(
                "Too many signatures: {} (max: {})",
                signatures_count, MAX_SIGNATURES
            );
            return Err(WSError::TooManySignatures(MAX_SIGNATURES));
        }
        let mut signatures = Vec::with_capacity(signatures_count);
        for _ in 0..signatures_count {
            let bin = varint::get_slice(&mut reader)?;
            if let Ok(signature) = SignatureForHashes::deserialize(bin) {
                signatures.push(signature);
            }
        }
        Ok(Self { hashes, signatures })
    }
}

impl SignatureData {
    pub fn serialize(&self) -> Result<Vec<u8>, WSError> {
        let mut writer = BufWriter::new(Vec::new());
        varint::put(&mut writer, self.specification_version as _)?;
        varint::put(&mut writer, self.content_type as _)?;
        varint::put(&mut writer, self.hash_function as _)?;
        varint::put(&mut writer, self.signed_hashes_set.len() as _)?;
        for signed_hashes in &self.signed_hashes_set {
            varint::put_slice(&mut writer, &signed_hashes.serialize()?)?;
        }
        writer
            .into_inner()
            .map_err(|e| WSError::IOError(std::io::Error::other(format!("buffer flush failed: {}", e))))
    }

    pub fn deserialize(bin: impl AsRef<[u8]>) -> Result<Self, WSError> {
        let mut reader = BufReader::new(bin.as_ref());
        let specification_version = varint::get7(&mut reader)?;
        if specification_version != SIGNATURE_VERSION {
            debug!(
                "Unsupported specification version: {:02x}",
                specification_version
            );
            return Err(WSError::ParseError);
        }
        let content_type = varint::get7(&mut reader)?;
        if content_type != SIGNATURE_WASM_MODULE_CONTENT_TYPE {
            debug!("Unsupported content type: {:02x}", content_type);
            return Err(WSError::ParseError);
        }
        let hash_function = varint::get7(&mut reader)?;
        let signed_hashes_count = varint::get32(&mut reader)? as _;
        if signed_hashes_count > MAX_HASHES {
            debug!(
                "Too many hashes: {} (max: {})",
                signed_hashes_count, MAX_HASHES
            );
            return Err(WSError::TooManyHashes(MAX_HASHES));
        }
        let mut signed_hashes_set = Vec::with_capacity(signed_hashes_count);
        for _ in 0..signed_hashes_count {
            let bin = varint::get_slice(&mut reader)?;
            let signed_hashes = SignedHashes::deserialize(bin)?;
            signed_hashes_set.push(signed_hashes);
        }
        Ok(Self {
            specification_version,
            content_type,
            hash_function,
            signed_hashes_set,
        })
    }
}

pub fn new_delimiter_section() -> Result<Section, WSError> {
    let mut custom_payload = vec![0u8; 16];
    getrandom::fill(&mut custom_payload)
        .map_err(|_| WSError::InternalError("RNG error".to_string()))?;
    Ok(Section::Custom(CustomSection::new(
        SIGNATURE_SECTION_DELIMITER_NAME.to_string(),
        custom_payload,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_for_hashes_serialize_no_key_id() {
        let sig = SignatureForHashes {
            key_id: None,
            alg_id: ED25519_PK_ID,
            signature: vec![1, 2, 3, 4],
            certificate_chain: None,
        };
        let serialized = sig.serialize().unwrap();
        assert!(!serialized.is_empty());
        // First byte should be 0 (no key_id)
        assert_eq!(serialized[0], 0);
    }

    #[test]
    fn test_signature_for_hashes_serialize_with_key_id() {
        let sig = SignatureForHashes {
            key_id: Some(vec![10, 20, 30]),
            alg_id: ED25519_PK_ID,
            signature: vec![1, 2, 3, 4],
            certificate_chain: None,
        };
        let serialized = sig.serialize().unwrap();
        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_signature_for_hashes_deserialize() {
        let original = SignatureForHashes {
            key_id: Some(vec![5, 6, 7]),
            alg_id: ED25519_PK_ID,
            signature: vec![11, 22, 33, 44],
            certificate_chain: None,
        };
        let serialized = original.serialize().unwrap();
        let deserialized = SignatureForHashes::deserialize(&serialized).unwrap();
        assert_eq!(deserialized, original);
    }

    #[test]
    fn test_signature_for_hashes_roundtrip_no_key_id() {
        let original = SignatureForHashes {
            key_id: None,
            alg_id: ED25519_PK_ID,
            signature: vec![100, 101, 102],
            certificate_chain: None,
        };
        let serialized = original.serialize().unwrap();
        let deserialized = SignatureForHashes::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.key_id, None);
        assert_eq!(deserialized.alg_id, original.alg_id);
        assert_eq!(deserialized.signature, original.signature);
    }

    #[test]
    fn test_signed_hashes_serialize() {
        let signed = SignedHashes {
            hashes: vec![vec![1; 32], vec![2; 32]],
            signatures: vec![SignatureForHashes {
                key_id: None,
                alg_id: ED25519_PK_ID,
                signature: vec![9, 8, 7],
                certificate_chain: None,
            }],
        };
        let serialized = signed.serialize().unwrap();
        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_signed_hashes_deserialize() {
        let original = SignedHashes {
            hashes: vec![vec![42; 32]],
            signatures: vec![SignatureForHashes {
                key_id: Some(vec![1, 2]),
                alg_id: ED25519_PK_ID,
                signature: vec![3, 4, 5],
                certificate_chain: None,
            }],
        };
        let serialized = original.serialize().unwrap();
        let deserialized = SignedHashes::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.hashes.len(), 1);
        assert_eq!(deserialized.hashes[0], vec![42; 32]);
        assert_eq!(deserialized.signatures.len(), 1);
    }

    #[test]
    fn test_signed_hashes_too_many_hashes() {
        // Create data claiming to have more than MAX_HASHES
        let mut buf = Vec::new();
        varint::put(&mut buf, (MAX_HASHES + 1) as u64).unwrap();
        let result = SignedHashes::deserialize(&buf);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::TooManyHashes(_)));
    }

    #[test]
    fn test_signed_hashes_too_many_signatures() {
        // Create valid hashes section
        let mut buf = Vec::new();
        varint::put(&mut buf, 1u64).unwrap(); // 1 hash
        buf.extend_from_slice(&[0u8; 32]); // The hash

        // Add too many signatures
        varint::put(&mut buf, (MAX_SIGNATURES + 1) as u64).unwrap();

        let result = SignedHashes::deserialize(&buf);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::TooManySignatures(_)));
    }

    #[test]
    fn test_signature_data_serialize() {
        let data = SignatureData {
            specification_version: SIGNATURE_VERSION,
            content_type: SIGNATURE_WASM_MODULE_CONTENT_TYPE,
            hash_function: 0x01,
            signed_hashes_set: vec![SignedHashes {
                hashes: vec![vec![99; 32]],
                signatures: vec![],
            }],
        };
        let serialized = data.serialize().unwrap();
        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_signature_data_deserialize() {
        let original = SignatureData {
            specification_version: SIGNATURE_VERSION,
            content_type: SIGNATURE_WASM_MODULE_CONTENT_TYPE,
            hash_function: 0x01,
            signed_hashes_set: vec![SignedHashes {
                hashes: vec![vec![55; 32]],
                signatures: vec![SignatureForHashes {
                    key_id: None,
                    alg_id: ED25519_PK_ID,
                    signature: vec![1, 2, 3],
                    certificate_chain: None,
                }],
            }],
        };
        let serialized = original.serialize().unwrap();
        let deserialized = SignatureData::deserialize(&serialized).unwrap();
        assert_eq!(
            deserialized.specification_version,
            original.specification_version
        );
        assert_eq!(deserialized.content_type, original.content_type);
        assert_eq!(deserialized.hash_function, original.hash_function);
        assert_eq!(deserialized.signed_hashes_set.len(), 1);
    }

    #[test]
    fn test_signature_data_roundtrip() {
        let original = SignatureData {
            specification_version: SIGNATURE_VERSION,
            content_type: SIGNATURE_WASM_MODULE_CONTENT_TYPE,
            hash_function: 0x02,
            signed_hashes_set: vec![
                SignedHashes {
                    hashes: vec![vec![1; 32], vec![2; 32]],
                    signatures: vec![SignatureForHashes {
                        key_id: Some(vec![10, 11]),
                        alg_id: ED25519_PK_ID,
                        signature: vec![20, 21, 22],
                        certificate_chain: None,
                    }],
                },
                SignedHashes {
                    hashes: vec![vec![3; 32]],
                    signatures: vec![],
                },
            ],
        };

        let serialized = original.serialize().unwrap();
        let deserialized = SignatureData::deserialize(&serialized).unwrap();

        assert_eq!(deserialized, original);
    }

    #[test]
    fn test_new_delimiter_section() {
        let section = new_delimiter_section().unwrap();
        assert!(section.is_signature_delimiter());

        if let Section::Custom(custom) = section {
            assert_eq!(custom.name(), SIGNATURE_SECTION_DELIMITER_NAME);
            assert_eq!(custom.payload().len(), 16);
        } else {
            panic!("Expected custom section");
        }
    }

    #[test]
    fn test_new_delimiter_sections_are_unique() {
        let section1 = new_delimiter_section().unwrap();
        let section2 = new_delimiter_section().unwrap();

        // Payloads should be different (random)
        assert_ne!(section1.payload(), section2.payload());
    }
}
