//! Fuzz target for WASM module parsing
//!
//! This target tests the WASM module deserialization which handles:
//! - Module header validation (magic bytes + version)
//! - Section parsing (ID + length + payload)
//! - Custom section name parsing (varint length + UTF-8 string)
//! - Signature section extraction
//!
//! Security concerns:
//! - Buffer overflows when reading section payloads
//! - Integer overflows in section length calculations
//! - Memory exhaustion via large section lengths
//! - UTF-8 validation in custom section names
//! - Malformed section IDs
//! - Truncated input handling

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use wsc::{Module, Section, SectionLike};

fuzz_target!(|data: &[u8]| {
    // Test full module deserialization
    let mut cursor = Cursor::new(data);
    if let Ok(module) = Module::deserialize(&mut cursor) {
        // Exercise module serialization (roundtrip test)
        let mut output = Vec::new();
        let _ = module.serialize(&mut output);

        // Check each section
        for section in &module.sections {
            // Access section properties
            let _ = section.id();
            let _ = section.payload();
            let _ = section.display(false);
            let _ = section.display(true);

            // Check signature-related methods
            let _ = section.is_signature_header();
            let _ = section.is_signature_delimiter();
        }
    }

    // Test streaming section parsing
    if data.len() >= 8 {
        let mut cursor = Cursor::new(data);
        if let Ok(stream) = Module::init_from_reader(&mut cursor) {
            if let Ok(sections_iter) = Module::iterate(stream) {
                for section_result in sections_iter.take(100) {
                    // Limit iterations to prevent DoS
                    if let Ok(section) = section_result {
                        let _ = section.id();
                        let _ = section.payload();
                    }
                }
            }
        }
    }

    // Test individual section deserialization
    let mut cursor = Cursor::new(data);
    if let Ok(Some(section)) = Section::deserialize(&mut cursor) {
        // Try to serialize it back
        let mut output = Vec::new();
        let _ = section.serialize(&mut output);
    }
});
