/// Variable-length integer encoding (LEB128)
///
/// This module provides functions for reading and writing variable-length
/// integers in the LEB128 format used by WebAssembly modules.
pub mod varint;

use crate::signature::*;

use ct_codecs::{Encoder, Hex};
use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, prelude::*};
use std::path::Path;
use std::str;

const WASM_HEADER: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
const WASM_COMPONENT_HEADER: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
pub type Header = [u8; 8];

/// A section identifier.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum SectionId {
    CustomSection,
    Type,
    Import,
    Function,
    Table,
    Memory,
    Global,
    Export,
    Start,
    Element,
    Code,
    Data,
    Extension(u8),
}

impl From<u8> for SectionId {
    fn from(v: u8) -> Self {
        match v {
            0 => SectionId::CustomSection,
            1 => SectionId::Type,
            2 => SectionId::Import,
            3 => SectionId::Function,
            4 => SectionId::Table,
            5 => SectionId::Memory,
            6 => SectionId::Global,
            7 => SectionId::Export,
            8 => SectionId::Start,
            9 => SectionId::Element,
            10 => SectionId::Code,
            11 => SectionId::Data,
            x => SectionId::Extension(x),
        }
    }
}

impl From<SectionId> for u8 {
    fn from(v: SectionId) -> Self {
        match v {
            SectionId::CustomSection => 0,
            SectionId::Type => 1,
            SectionId::Import => 2,
            SectionId::Function => 3,
            SectionId::Table => 4,
            SectionId::Memory => 5,
            SectionId::Global => 6,
            SectionId::Export => 7,
            SectionId::Start => 8,
            SectionId::Element => 9,
            SectionId::Code => 10,
            SectionId::Data => 11,
            SectionId::Extension(x) => x,
        }
    }
}

impl fmt::Display for SectionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SectionId::CustomSection => write!(f, "custom section"),
            SectionId::Type => write!(f, "types section"),
            SectionId::Import => write!(f, "imports section"),
            SectionId::Function => write!(f, "functions section"),
            SectionId::Table => write!(f, "table section"),
            SectionId::Memory => write!(f, "memory section"),
            SectionId::Global => write!(f, "global section"),
            SectionId::Export => write!(f, "exports section"),
            SectionId::Start => write!(f, "start section"),
            SectionId::Element => write!(f, "elements section"),
            SectionId::Code => write!(f, "code section"),
            SectionId::Data => write!(f, "data section"),
            SectionId::Extension(x) => write!(f, "section id#{x}"),
        }
    }
}

/// Common functions for a module section.
pub trait SectionLike {
    fn id(&self) -> SectionId;
    fn payload(&self) -> &[u8];
    fn display(&self, verbose: bool) -> String;
}

/// A standard section.
#[derive(Debug, Clone)]
pub struct StandardSection {
    id: SectionId,
    payload: Vec<u8>,
}

impl StandardSection {
    /// Create a new standard section.
    pub fn new(id: SectionId, payload: Vec<u8>) -> Self {
        Self { id, payload }
    }
}

impl SectionLike for StandardSection {
    /// Return the identifier of the section.
    fn id(&self) -> SectionId {
        self.id
    }

    /// Return the payload of the section.
    fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Human-readable representation of the section.
    fn display(&self, _verbose: bool) -> String {
        self.id().to_string()
    }
}

/// A custom section.
#[derive(Debug, Clone, Default)]
pub struct CustomSection {
    name: String,
    payload: Vec<u8>,
}

impl CustomSection {
    /// Create a new custom section.
    pub fn new(name: String, payload: Vec<u8>) -> Self {
        Self { name, payload }
    }

    /// Return the name of the custom section.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the custom section as an array of bytes.
    ///
    /// This includes the data itself, but also the size and name of the custom section.
    pub fn outer_payload(&self) -> Result<Vec<u8>, WSError> {
        let mut writer = io::Cursor::new(vec![]);
        varint::put(&mut writer, self.name.len() as _)?;
        writer.write_all(self.name.as_bytes())?;
        writer.write_all(&self.payload)?;
        Ok(writer.into_inner())
    }
}

impl SectionLike for CustomSection {
    fn id(&self) -> SectionId {
        SectionId::CustomSection
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn display(&self, verbose: bool) -> String {
        if !verbose {
            return format!("custom section: [{}]", self.name());
        }

        match self.name() {
            SIGNATURE_SECTION_DELIMITER_NAME => format!(
                "custom section: [{}]\n- delimiter: [{}]\n",
                self.name,
                Hex::encode_to_string(self.payload()).unwrap_or_else(|_| "<hex encoding error>".to_string())
            ),
            SIGNATURE_SECTION_HEADER_NAME => {
                let signature_data = match SignatureData::deserialize(self.payload()) {
                    Ok(signature_data) => signature_data,
                    _ => return "undecodable signature header".to_string(),
                };
                let mut s = String::new();
                let _ = writeln!(
                    s,
                    "- specification version: 0x{:02x}",
                    signature_data.specification_version,
                );
                let _ = writeln!(s, "- content_type: 0x{:02x}", signature_data.content_type);
                let _ = writeln!(
                    s,
                    "- hash function: 0x{:02x} (SHA-256)",
                    signature_data.hash_function
                );
                let _ = writeln!(s, "- (hashes,signatures) set:");
                for signed_parts in &signature_data.signed_hashes_set {
                    let _ = writeln!(s, "  - hashes:");
                    for hash in &signed_parts.hashes {
                        let hex = Hex::encode_to_string(hash).unwrap_or_else(|_| "<hex error>".to_string());
                        let _ = writeln!(s, "    - [{}]", hex);
                    }
                    let _ = writeln!(s, "  - signatures:");
                    for signature in &signed_parts.signatures {
                        let hex = Hex::encode_to_string(&signature.signature).unwrap_or_else(|_| "<hex error>".to_string());
                        let _ = write!(s, "    - [{}]", hex);
                        match &signature.key_id {
                            None => { let _ = writeln!(s, " (no key id)"); }
                            Some(key_id) => {
                                let key_hex = Hex::encode_to_string(key_id).unwrap_or_else(|_| "<hex error>".to_string());
                                let _ = writeln!(s, " (key id: [{}])", key_hex);
                            }
                        }
                    }
                }
                format!("custom section: [{}]\n{}", self.name(), s)
            }
            _ => format!("custom section: [{}]", self.name()),
        }
    }
}

/// A WebAssembly module section.
///
/// It is recommended to import the `SectionLike` trait for additional functions.
#[derive(Clone)]
pub enum Section {
    /// A standard section.
    Standard(StandardSection),
    /// A custom section.
    Custom(CustomSection),
}

impl SectionLike for Section {
    fn id(&self) -> SectionId {
        match self {
            Section::Standard(s) => s.id(),
            Section::Custom(s) => s.id(),
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            Section::Standard(s) => s.payload(),
            Section::Custom(s) => s.payload(),
        }
    }

    fn display(&self, verbose: bool) -> String {
        match self {
            Section::Standard(s) => s.display(verbose),
            Section::Custom(s) => s.display(verbose),
        }
    }
}

impl Section {
    /// Create a new section with the given identifier and payload.
    pub fn new(id: SectionId, payload: Vec<u8>) -> Result<Self, WSError> {
        match id {
            SectionId::CustomSection => {
                let mut reader = io::Cursor::new(payload);
                let name_len = varint::get32(&mut reader)? as usize;
                let mut name_slice = vec![0u8; name_len];
                reader.read_exact(&mut name_slice)?;
                let name = str::from_utf8(&name_slice)?.to_string();
                let mut payload = Vec::new();
                let len = reader.read_to_end(&mut payload)?;
                payload.truncate(len);
                Ok(Section::Custom(CustomSection::new(name, payload)))
            }
            _ => Ok(Section::Standard(StandardSection::new(id, payload))),
        }
    }

    /// Create a section from its standard serialized representation.
    pub fn deserialize(reader: &mut impl Read) -> Result<Option<Self>, WSError> {
        let id = match varint::get7(reader) {
            Ok(id) => SectionId::from(id),
            Err(WSError::Eof) => return Ok(None),
            Err(e) => return Err(e),
        };
        let len = varint::get32(reader)? as usize;
        let mut payload = vec![0u8; len];
        reader.read_exact(&mut payload)?;
        let section = Section::new(id, payload)?;
        Ok(Some(section))
    }

    /// Serialize a section.
    pub fn serialize(&self, writer: &mut impl Write) -> Result<(), WSError> {
        let outer_payload;
        let payload = match self {
            Section::Standard(s) => s.payload(),
            Section::Custom(s) => {
                outer_payload = s.outer_payload()?;
                &outer_payload
            }
        };
        varint::put(writer, u8::from(self.id()) as _)?;
        varint::put(writer, payload.len() as _)?;
        writer.write_all(payload)?;
        Ok(())
    }

    /// Return `true` if the section contains the module's signatures.
    pub fn is_signature_header(&self) -> bool {
        match self {
            Section::Standard(_) => false,
            Section::Custom(s) => s.is_signature_header(),
        }
    }

    /// Return `true` if the section is a signature delimiter.
    pub fn is_signature_delimiter(&self) -> bool {
        match self {
            Section::Standard(_) => false,
            Section::Custom(s) => s.is_signature_delimiter(),
        }
    }
}

impl CustomSection {
    /// Return `true` if the section contains the module's signatures.
    pub fn is_signature_header(&self) -> bool {
        self.name() == SIGNATURE_SECTION_HEADER_NAME
    }

    /// Return `true` if the section is a signature delimiter.
    pub fn is_signature_delimiter(&self) -> bool {
        self.name() == SIGNATURE_SECTION_DELIMITER_NAME
    }

    /// If the section contains the module's signature, deserializes it into a `SignatureData` object
    /// containing the signatures and the hashes.
    pub fn signature_data(&self) -> Result<SignatureData, WSError> {
        let header_payload =
            SignatureData::deserialize(self.payload()).map_err(|_| WSError::ParseError)?;
        Ok(header_payload)
    }
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.display(false))
    }
}

impl fmt::Debug for Section {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.display(true))
    }
}

/// A WebAssembly module.
#[derive(Debug, Clone, Default)]
pub struct Module {
    pub header: Header,
    pub sections: Vec<Section>,
}

impl Module {
    /// Deserialize a WebAssembly module from the given reader.
    pub fn deserialize(reader: &mut impl Read) -> Result<Self, WSError> {
        let stream = Self::init_from_reader(reader)?;
        let header = stream.header;
        let it = Self::iterate(stream)?;
        let mut sections = Vec::new();
        for section in it {
            sections.push(section?);
        }
        Ok(Module { header, sections })
    }

    /// Deserialize a WebAssembly module from the given file.
    pub fn deserialize_from_file(file: impl AsRef<Path>) -> Result<Self, WSError> {
        let path = file.as_ref();
        let fp = File::open(path).map_err(|e| {
            WSError::InternalError(format!(
                "Failed to open input file '{}': {}",
                path.display(),
                e
            ))
        })?;
        Self::deserialize(&mut BufReader::new(fp))
    }

    /// Serialize a WebAssembly module to the given writer.
    pub fn serialize(&self, writer: &mut impl Write) -> Result<(), WSError> {
        writer.write_all(&self.header)?;
        for section in &self.sections {
            section.serialize(writer)?;
        }
        Ok(())
    }

    /// Serialize a WebAssembly module to the given file.
    pub fn serialize_to_file(&self, file: impl AsRef<Path>) -> Result<(), WSError> {
        let path = file.as_ref();
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                WSError::InternalError(format!(
                    "Failed to create parent directory for '{}': {}",
                    path.display(),
                    e
                ))
            })?;
        }
        let fp = File::create(path).map_err(|e| {
            WSError::InternalError(format!(
                "Failed to create output file '{}': {}",
                path.display(),
                e
            ))
        })?;
        self.serialize(&mut BufWriter::new(fp))
    }

    /// Parse the module's header. This function must be called before `stream()`.
    pub fn init_from_reader<T: Read>(reader: &mut T) -> Result<ModuleStreamReader<'_, T>, WSError> {
        let mut header = Header::default();
        reader.read_exact(&mut header)?;
        if header != WASM_HEADER && header != WASM_COMPONENT_HEADER {
            return Err(WSError::UnsupportedModuleType);
        }
        Ok(ModuleStreamReader { reader, header })
    }

    /// Return an iterator over the sections of a WebAssembly module.    
    ///
    /// The module is read in a streaming fashion, and doesn't have to be fully loaded into memory.
    pub fn iterate<T: Read>(
        module_stream: ModuleStreamReader<T>,
    ) -> Result<SectionsIterator<T>, WSError> {
        Ok(SectionsIterator {
            reader: module_stream.reader,
        })
    }
}

pub struct ModuleStreamReader<'t, T: Read> {
    reader: &'t mut T,
    header: Header,
}

/// An iterator over the sections of a WebAssembly module.
pub struct SectionsIterator<'t, T: Read> {
    reader: &'t mut T,
}

impl<'t, T: Read> Iterator for SectionsIterator<'t, T> {
    type Item = Result<Section, WSError>;

    fn next(&mut self) -> Option<Self::Item> {
        match Section::deserialize(self.reader) {
            Err(e) => Some(Err(e)),
            Ok(None) => None,
            Ok(Some(section)) => Some(Ok(section)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_id_from_u8() {
        assert_eq!(SectionId::from(0), SectionId::CustomSection);
        assert_eq!(SectionId::from(1), SectionId::Type);
        assert_eq!(SectionId::from(2), SectionId::Import);
        assert_eq!(SectionId::from(3), SectionId::Function);
        assert_eq!(SectionId::from(4), SectionId::Table);
        assert_eq!(SectionId::from(5), SectionId::Memory);
        assert_eq!(SectionId::from(6), SectionId::Global);
        assert_eq!(SectionId::from(7), SectionId::Export);
        assert_eq!(SectionId::from(8), SectionId::Start);
        assert_eq!(SectionId::from(9), SectionId::Element);
        assert_eq!(SectionId::from(10), SectionId::Code);
        assert_eq!(SectionId::from(11), SectionId::Data);
        assert_eq!(SectionId::from(99), SectionId::Extension(99));
    }

    #[test]
    fn test_section_id_to_u8() {
        assert_eq!(u8::from(SectionId::CustomSection), 0);
        assert_eq!(u8::from(SectionId::Type), 1);
        assert_eq!(u8::from(SectionId::Import), 2);
        assert_eq!(u8::from(SectionId::Function), 3);
        assert_eq!(u8::from(SectionId::Table), 4);
        assert_eq!(u8::from(SectionId::Memory), 5);
        assert_eq!(u8::from(SectionId::Global), 6);
        assert_eq!(u8::from(SectionId::Export), 7);
        assert_eq!(u8::from(SectionId::Start), 8);
        assert_eq!(u8::from(SectionId::Element), 9);
        assert_eq!(u8::from(SectionId::Code), 10);
        assert_eq!(u8::from(SectionId::Data), 11);
        assert_eq!(u8::from(SectionId::Extension(99)), 99);
    }

    #[test]
    fn test_section_id_display() {
        assert_eq!(SectionId::CustomSection.to_string(), "custom section");
        assert_eq!(SectionId::Type.to_string(), "types section");
        assert_eq!(SectionId::Import.to_string(), "imports section");
        assert_eq!(SectionId::Function.to_string(), "functions section");
        assert_eq!(SectionId::Table.to_string(), "table section");
        assert_eq!(SectionId::Memory.to_string(), "memory section");
        assert_eq!(SectionId::Global.to_string(), "global section");
        assert_eq!(SectionId::Export.to_string(), "exports section");
        assert_eq!(SectionId::Start.to_string(), "start section");
        assert_eq!(SectionId::Element.to_string(), "elements section");
        assert_eq!(SectionId::Code.to_string(), "code section");
        assert_eq!(SectionId::Data.to_string(), "data section");
        assert_eq!(SectionId::Extension(42).to_string(), "section id#42");
    }

    #[test]
    fn test_standard_section_new() {
        let payload = vec![1, 2, 3, 4];
        let section = StandardSection::new(SectionId::Type, payload.clone());
        assert_eq!(section.id(), SectionId::Type);
        assert_eq!(section.payload(), &payload);
    }

    #[test]
    fn test_standard_section_display() {
        let section = StandardSection::new(SectionId::Code, vec![1, 2, 3]);
        assert_eq!(section.display(false), "code section");
        assert_eq!(section.display(true), "code section");
    }

    #[test]
    fn test_custom_section_new() {
        let name = "test_section".to_string();
        let payload = vec![5, 6, 7, 8];
        let section = CustomSection::new(name.clone(), payload.clone());
        assert_eq!(section.name(), "test_section");
        assert_eq!(section.id(), SectionId::CustomSection);
        assert_eq!(section.payload(), &payload);
    }

    #[test]
    fn test_custom_section_display() {
        let section = CustomSection::new("my_section".to_string(), vec![1, 2, 3]);
        assert_eq!(section.display(false), "custom section: [my_section]");
    }

    #[test]
    fn test_custom_section_outer_payload() {
        let name = "test".to_string();
        let payload = vec![1, 2, 3];
        let section = CustomSection::new(name.clone(), payload.clone());

        let outer = section.outer_payload().unwrap();
        // Should contain: length of name (varint), name bytes, payload bytes
        assert!(outer.len() >= name.len() + payload.len());
    }

    #[test]
    fn test_section_standard_wrapper() {
        let std_section = StandardSection::new(SectionId::Memory, vec![9, 10]);
        let section = Section::Standard(std_section);

        assert_eq!(section.id(), SectionId::Memory);
        assert_eq!(section.payload(), &[9, 10]);
        assert!(section.display(false).contains("memory"));
    }

    #[test]
    fn test_section_custom_wrapper() {
        let custom_section = CustomSection::new("wrapper_test".to_string(), vec![11, 12]);
        let section = Section::Custom(custom_section);

        assert_eq!(section.id(), SectionId::CustomSection);
        assert_eq!(section.payload(), &[11, 12]);
        assert!(section.display(false).contains("wrapper_test"));
    }

    #[test]
    fn test_custom_section_is_signature_header() {
        let sig_section = CustomSection::new(SIGNATURE_SECTION_HEADER_NAME.to_string(), vec![]);
        assert!(sig_section.is_signature_header());
        assert!(!sig_section.is_signature_delimiter());

        let other_section = CustomSection::new("other".to_string(), vec![]);
        assert!(!other_section.is_signature_header());
    }

    #[test]
    fn test_custom_section_is_signature_delimiter() {
        let delim_section =
            CustomSection::new(SIGNATURE_SECTION_DELIMITER_NAME.to_string(), vec![]);
        assert!(delim_section.is_signature_delimiter());
        assert!(!delim_section.is_signature_header());

        let other_section = CustomSection::new("other".to_string(), vec![]);
        assert!(!other_section.is_signature_delimiter());
    }

    #[test]
    fn test_section_is_signature_methods() {
        let sig_header = Section::Custom(CustomSection::new(
            SIGNATURE_SECTION_HEADER_NAME.to_string(),
            vec![],
        ));
        assert!(sig_header.is_signature_header());
        assert!(!sig_header.is_signature_delimiter());

        let sig_delim = Section::Custom(CustomSection::new(
            SIGNATURE_SECTION_DELIMITER_NAME.to_string(),
            vec![],
        ));
        assert!(sig_delim.is_signature_delimiter());
        assert!(!sig_delim.is_signature_header());

        let std_section = Section::Standard(StandardSection::new(SectionId::Code, vec![]));
        assert!(!std_section.is_signature_header());
        assert!(!std_section.is_signature_delimiter());
    }

    #[test]
    fn test_module_default() {
        let module = Module::default();
        assert_eq!(module.header, [0; 8]);
        assert_eq!(module.sections.len(), 0);
    }

    #[test]
    fn test_module_deserialize_invalid_header() {
        let bad_header = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut reader = io::Cursor::new(bad_header);
        let result = Module::deserialize(&mut reader);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WSError::UnsupportedModuleType
        ));
    }

    #[test]
    fn test_module_deserialize_wasm_header() {
        let data = WASM_HEADER.to_vec();
        // Add empty module (no sections)
        let mut reader = io::Cursor::new(data);
        let result = Module::deserialize(&mut reader);
        assert!(result.is_ok());
        let module = result.unwrap();
        assert_eq!(module.header, WASM_HEADER);
    }

    #[test]
    fn test_module_deserialize_component_header() {
        let data = WASM_COMPONENT_HEADER.to_vec();
        // Add empty module (no sections)
        let mut reader = io::Cursor::new(data);
        let result = Module::deserialize(&mut reader);
        assert!(result.is_ok());
        let module = result.unwrap();
        assert_eq!(module.header, WASM_COMPONENT_HEADER);
    }

    #[test]
    fn test_module_serialize_roundtrip() {
        // Create a simple module
        let module = Module {
            header: WASM_HEADER,
            sections: vec![],
        };

        // Serialize it
        let mut buffer = Vec::new();
        module.serialize(&mut buffer).unwrap();

        // Deserialize it back
        let mut reader = io::Cursor::new(buffer);
        let module2 = Module::deserialize(&mut reader).unwrap();

        assert_eq!(module2.header, WASM_HEADER);
        assert_eq!(module2.sections.len(), 0);
    }

    #[test]
    fn test_section_display_formats() {
        let section = Section::Standard(StandardSection::new(SectionId::Export, vec![]));
        let display = format!("{}", section);
        assert!(display.contains("exports"));

        let debug = format!("{:?}", section);
        assert!(debug.contains("exports"));
    }

    #[test]
    fn test_section_new_custom() {
        // Create a custom section with name and payload
        let mut payload = Vec::new();
        varint::put(&mut payload, 4u64).unwrap(); // name length
        payload.extend_from_slice(b"test");
        payload.extend_from_slice(&[1, 2, 3]);

        let section = Section::new(SectionId::CustomSection, payload).unwrap();
        if let Section::Custom(custom) = section {
            assert_eq!(custom.name(), "test");
            assert_eq!(custom.payload(), &[1, 2, 3]);
        } else {
            panic!("Expected custom section");
        }
    }

    #[test]
    fn test_section_new_standard() {
        let payload = vec![10, 20, 30];
        let section = Section::new(SectionId::Code, payload.clone()).unwrap();
        if let Section::Standard(std) = section {
            assert_eq!(std.id(), SectionId::Code);
            assert_eq!(std.payload(), &payload);
        } else {
            panic!("Expected standard section");
        }
    }

    #[test]
    fn test_section_serialize_standard() {
        let section = Section::Standard(StandardSection::new(SectionId::Memory, vec![5, 6, 7]));
        let mut buffer = Vec::new();
        section.serialize(&mut buffer).unwrap();
        assert!(!buffer.is_empty());
    }

    #[test]
    fn test_section_serialize_custom() {
        let section = Section::Custom(CustomSection::new("my_custom".to_string(), vec![8, 9]));
        let mut buffer = Vec::new();
        section.serialize(&mut buffer).unwrap();
        assert!(!buffer.is_empty());
    }

    #[test]
    fn test_section_deserialize_eof() {
        let empty_data = vec![];
        let mut reader = io::Cursor::new(empty_data);
        let result = Section::deserialize(&mut reader).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_section_deserialize_standard() {
        // Create a standard section manually
        let mut data = Vec::new();
        varint::put(&mut data, u8::from(SectionId::Table) as u64).unwrap();
        varint::put(&mut data, 3u64).unwrap(); // payload length
        data.extend_from_slice(&[1, 2, 3]);

        let mut reader = io::Cursor::new(data);
        let section = Section::deserialize(&mut reader).unwrap().unwrap();
        assert_eq!(section.id(), SectionId::Table);
        assert_eq!(section.payload(), &[1, 2, 3]);
    }

    #[test]
    fn test_section_deserialize_roundtrip() {
        let original = Section::Standard(StandardSection::new(SectionId::Global, vec![42, 43, 44]));
        let mut buffer = Vec::new();
        original.serialize(&mut buffer).unwrap();

        let mut reader = io::Cursor::new(buffer);
        let deserialized = Section::deserialize(&mut reader).unwrap().unwrap();
        assert_eq!(deserialized.id(), original.id());
        assert_eq!(deserialized.payload(), original.payload());
    }

    #[test]
    fn test_custom_section_signature_data_invalid() {
        let custom = CustomSection::new(SIGNATURE_SECTION_HEADER_NAME.to_string(), vec![1, 2, 3]);
        let result = custom.signature_data();
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_section_display_verbose() {
        let custom = CustomSection::new("verbose_test".to_string(), vec![10, 20]);
        let display = custom.display(true);
        assert!(display.contains("verbose_test"));
    }

    #[test]
    fn test_custom_section_display_delimiter() {
        let custom = CustomSection::new(
            SIGNATURE_SECTION_DELIMITER_NAME.to_string(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        );
        let display = custom.display(true);
        assert!(display.contains("delimiter"));
    }

    #[test]
    fn test_module_serialize_with_sections() {
        let module = Module {
            header: WASM_HEADER,
            sections: vec![
                Section::Standard(StandardSection::new(SectionId::Type, vec![1])),
                Section::Standard(StandardSection::new(SectionId::Function, vec![2])),
            ],
        };

        let mut buffer = Vec::new();
        module.serialize(&mut buffer).unwrap();

        // Should have header + sections
        assert!(buffer.len() > 8);
    }

    #[test]
    fn test_module_deserialize_with_sections() {
        let mut data = WASM_HEADER.to_vec();
        // Add a simple Type section
        varint::put(&mut data, u8::from(SectionId::Type) as u64).unwrap();
        varint::put(&mut data, 2u64).unwrap();
        data.extend_from_slice(&[10, 20]);

        let mut reader = io::Cursor::new(data);
        let module = Module::deserialize(&mut reader).unwrap();
        assert_eq!(module.sections.len(), 1);
        assert_eq!(module.sections[0].id(), SectionId::Type);
    }

    #[test]
    fn test_module_sections_iterator() {
        let mut data = WASM_HEADER.to_vec();
        // Add two sections
        varint::put(&mut data, u8::from(SectionId::Memory) as u64).unwrap();
        varint::put(&mut data, 1u64).unwrap();
        data.push(99);

        varint::put(&mut data, u8::from(SectionId::Global) as u64).unwrap();
        varint::put(&mut data, 1u64).unwrap();
        data.push(88);

        let mut reader = io::Cursor::new(&data);
        let stream = Module::init_from_reader(&mut reader).unwrap();
        let sections: Vec<_> = Module::iterate(stream).unwrap().collect();

        assert_eq!(sections.len(), 2);
        assert!(sections[0].is_ok());
        assert!(sections[1].is_ok());
    }

    #[test]
    fn test_section_id_copy() {
        let id1 = SectionId::Code;
        let id2 = id1;
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_section_extension_id() {
        let ext_id = SectionId::Extension(42);
        assert_eq!(u8::from(ext_id), 42);
        assert_eq!(ext_id, SectionId::from(42));
    }

    #[test]
    fn test_custom_section_default() {
        let custom = CustomSection::default();
        assert_eq!(custom.name(), "");
        assert_eq!(custom.payload(), &[] as &[u8]);
    }
}
