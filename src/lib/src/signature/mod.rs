mod hash;
pub mod keyless;
mod keys;
mod matrix;
mod multi;
mod sig_sections;
mod simple;

pub use keys::*;
pub use matrix::*;

pub(crate) use hash::*;

// Re-export signature data structures for fuzzing and advanced use cases
pub use sig_sections::{
    SignatureData, SignedHashes, SignatureForHashes,
    SIGNATURE_SECTION_HEADER_NAME, SIGNATURE_SECTION_DELIMITER_NAME,
    MAX_HASHES, MAX_SIGNATURES, new_delimiter_section,
};
