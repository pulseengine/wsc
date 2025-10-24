use crate::signature::*;
use crate::wasm_module::*;

use log::*;

impl Module {
    /// Print the structure of a module to the standard output, mainly for debugging purposes.
    ///
    /// Set `verbose` to `true` in order to also print details about signature data.
    pub fn show(&self, verbose: bool) -> Result<(), WSError> {
        for (idx, section) in self.sections.iter().enumerate() {
            println!("{}:\t{}", idx, section.display(verbose));
        }
        Ok(())
    }

    /// Prepare a module for partial verification.
    ///
    /// The predicate should return `true` if a section is part of a set that can be verified,
    /// and `false` if the section can be ignored during verification.
    ///
    /// It is highly recommended to always include the standard sections in the signed set.
    pub fn split<P>(self, mut predicate: P) -> Result<Module, WSError>
    where
        P: FnMut(&Section) -> bool,
    {
        let mut out_sections = vec![];
        let mut flip = false;
        let mut last_was_delimiter = false;
        for (idx, section) in self.sections.into_iter().enumerate() {
            if section.is_signature_header() {
                info!("Module is already signed");
                out_sections.push(section);
                continue;
            }
            if section.is_signature_delimiter() {
                out_sections.push(section);
                last_was_delimiter = true;
                continue;
            }
            let section_can_be_signed = predicate(&section);
            if idx == 0 {
                flip = !section_can_be_signed;
            } else if section_can_be_signed == flip {
                if !last_was_delimiter {
                    let delimiter = new_delimiter_section()?;
                    out_sections.push(delimiter);
                }
                flip = !flip;
            }
            out_sections.push(section);
            last_was_delimiter = false;
        }
        if let Some(last_section) = out_sections.last()
            && !last_section.is_signature_delimiter()
        {
            let delimiter = new_delimiter_section()?;
            out_sections.push(delimiter);
        }
        Ok(Module {
            header: self.header,
            sections: out_sections,
        })
    }

    /// Detach the signature from a signed module.
    ///
    /// This function returns the module without the embedded signature,
    /// as well as the detached signature as a byte string.
    pub fn detach_signature(mut self) -> Result<(Module, Vec<u8>), WSError> {
        let mut out_sections = vec![];
        let mut sections = self.sections.into_iter();
        let detached_signature = match sections.next() {
            None => return Err(WSError::NoSignatures),
            Some(section) => {
                if !section.is_signature_header() {
                    return Err(WSError::NoSignatures);
                }
                section.payload().to_vec()
            }
        };
        for section in sections {
            out_sections.push(section);
        }
        self.sections = out_sections;
        debug!("Signature detached");
        Ok((self, detached_signature))
    }

    /// Embed a detached signature into a module.
    /// This function returns the module with embedded signature.
    pub fn attach_signature(mut self, detached_signature: &[u8]) -> Result<Module, WSError> {
        let mut out_sections = vec![];
        let sections = self.sections.into_iter();
        let signature_header = Section::Custom(CustomSection::new(
            SIGNATURE_SECTION_HEADER_NAME.to_string(),
            detached_signature.to_vec(),
        ));
        out_sections.push(signature_header);
        for section in sections {
            if section.is_signature_header() {
                return Err(WSError::SignatureAlreadyAttached);
            }
            out_sections.push(section);
        }
        self.sections = out_sections;
        debug!("Signature attached");
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_detach_signature_no_signatures() {
        let module = create_test_module();
        let result = module.detach_signature();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::NoSignatures));
    }

    #[test]
    fn test_detach_signature_with_signature() {
        let signature_data = vec![1, 2, 3, 4, 5];
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Custom(CustomSection::new(
                    SIGNATURE_SECTION_HEADER_NAME.to_string(),
                    signature_data.clone(),
                )),
                Section::Standard(StandardSection::new(SectionId::Type, vec![1, 2, 3])),
                Section::Standard(StandardSection::new(SectionId::Code, vec![4, 5, 6])),
            ],
        };

        let result = module.detach_signature();
        assert!(result.is_ok());
        let (new_module, detached_sig) = result.unwrap();
        assert_eq!(detached_sig, signature_data);
        assert_eq!(new_module.sections.len(), 2);
        assert!(!new_module.sections[0].is_signature_header());
    }

    #[test]
    fn test_attach_signature() {
        let module = create_test_module();
        let signature_data = vec![10, 20, 30];

        let result = module.attach_signature(&signature_data);
        assert!(result.is_ok());
        let signed_module = result.unwrap();

        // First section should be the signature
        assert_eq!(signed_module.sections.len(), 4);
        assert!(signed_module.sections[0].is_signature_header());
        assert_eq!(signed_module.sections[0].payload(), &signature_data);
    }

    #[test]
    fn test_attach_signature_already_signed() {
        let signature_data = vec![1, 2, 3];
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Custom(CustomSection::new(
                    SIGNATURE_SECTION_HEADER_NAME.to_string(),
                    signature_data.clone(),
                )),
                Section::Standard(StandardSection::new(SectionId::Code, vec![4, 5, 6])),
            ],
        };

        let new_signature = vec![7, 8, 9];
        let result = module.attach_signature(&new_signature);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WSError::SignatureAlreadyAttached
        ));
    }

    #[test]
    fn test_split_all_sections() {
        let module = create_test_module();

        // Predicate that includes all sections
        let result = module.split(|_| true);
        assert!(result.is_ok());
        let split_module = result.unwrap();

        // Should have original sections plus a delimiter at the end
        assert!(split_module.sections.len() >= 3);
        assert!(
            split_module
                .sections
                .last()
                .unwrap()
                .is_signature_delimiter()
        );
    }

    #[test]
    fn test_split_no_sections() {
        let module = create_test_module();

        // Predicate that includes no sections
        let result = module.split(|_| false);
        assert!(result.is_ok());
        let split_module = result.unwrap();

        // Should have delimiters inserted
        assert!(split_module.sections.len() > 3);
    }

    #[test]
    fn test_split_with_existing_signature() {
        let module = Module {
            header: [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            sections: vec![
                Section::Custom(CustomSection::new(
                    SIGNATURE_SECTION_HEADER_NAME.to_string(),
                    vec![1, 2, 3],
                )),
                Section::Standard(StandardSection::new(SectionId::Type, vec![4, 5, 6])),
            ],
        };

        let result = module.split(|_| true);
        assert!(result.is_ok());
        let split_module = result.unwrap();

        // Signature header should be preserved
        assert!(split_module.sections[0].is_signature_header());
    }

    #[test]
    fn test_split_selective() {
        let module = create_test_module();

        // Only include Type sections
        let result = module.split(|section| matches!(section.id(), SectionId::Type));
        assert!(result.is_ok());
        let split_module = result.unwrap();

        // Should have delimiters between different section types
        let has_delimiter = split_module
            .sections
            .iter()
            .any(|s| s.is_signature_delimiter());
        assert!(has_delimiter);
    }

    #[test]
    fn test_show_non_verbose() {
        let module = create_test_module();
        // Just verify it doesn't crash
        let result = module.show(false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_verbose() {
        let module = create_test_module();
        // Just verify it doesn't crash
        let result = module.show(true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_detach_attach_roundtrip() {
        let signature_data = vec![42, 43, 44];
        let original_module = create_test_module();

        // Attach a signature
        let signed_module = original_module.attach_signature(&signature_data).unwrap();

        // Detach it
        let (unsigned_module, detached_sig) = signed_module.detach_signature().unwrap();

        // Verify the signature matches
        assert_eq!(detached_sig, signature_data);

        // Verify we're back to original structure (same number of sections)
        assert_eq!(unsigned_module.sections.len(), 3);
    }
}
