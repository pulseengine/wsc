use std::io::{self, prelude::*};

use crate::error::*;

pub fn get7(reader: &mut impl Read) -> Result<u8, WSError> {
    let mut v: u8 = 0;
    for i in 0..1 {
        let mut byte = [0u8; 1];
        if let Err(e) = reader.read_exact(&mut byte) {
            return Err(if e.kind() == io::ErrorKind::UnexpectedEof {
                WSError::Eof
            } else {
                e.into()
            });
        };
        v |= (byte[0] & 0x7f) << (i * 7);
        if (byte[0] & 0x80) == 0 {
            return Ok(v);
        }
    }
    Err(WSError::ParseError)
}

pub fn get32(reader: &mut impl Read) -> Result<u32, WSError> {
    let mut v: u32 = 0;
    for i in 0..5 {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        v |= ((byte[0] & 0x7f) as u32) << (i * 7);
        if (byte[0] & 0x80) == 0 {
            return Ok(v);
        }
    }
    Err(WSError::ParseError)
}

pub fn put(writer: &mut impl Write, mut v: u64) -> Result<(), WSError> {
    let mut byte = [0u8; 1];
    loop {
        byte[0] = (v & 0x7f) as u8;
        if v > 0x7f {
            byte[0] |= 0x80;
        }
        writer.write_all(&byte)?;
        v >>= 7;
        if v == 0 {
            return Ok(());
        }
    }
}

pub fn put_slice(writer: &mut impl Write, bytes: impl AsRef<[u8]>) -> Result<(), WSError> {
    let bytes = bytes.as_ref();
    put(writer, bytes.len() as _)?;
    writer.write_all(bytes)?;
    Ok(())
}

pub fn get_slice(reader: &mut impl Read) -> Result<Vec<u8>, WSError> {
    let len = get32(reader)? as _;
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get7_single_byte() {
        let data = vec![0x42];
        let mut reader = io::Cursor::new(data);
        let result = get7(&mut reader).unwrap();
        assert_eq!(result, 0x42);
    }

    #[test]
    fn test_get7_max_value() {
        let data = vec![0x7F];
        let mut reader = io::Cursor::new(data);
        let result = get7(&mut reader).unwrap();
        assert_eq!(result, 0x7F);
    }

    #[test]
    fn test_get7_eof() {
        let data = vec![];
        let mut reader = io::Cursor::new(data);
        let result = get7(&mut reader);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSError::Eof));
    }

    #[test]
    fn test_get32_single_byte() {
        let data = vec![0x05];
        let mut reader = io::Cursor::new(data);
        let result = get32(&mut reader).unwrap();
        assert_eq!(result, 5);
    }

    #[test]
    fn test_get32_multi_byte() {
        // 128 = 0x80 0x01 in LEB128
        let data = vec![0x80, 0x01];
        let mut reader = io::Cursor::new(data);
        let result = get32(&mut reader).unwrap();
        assert_eq!(result, 128);
    }

    #[test]
    fn test_get32_large_value() {
        // 16384 = 0x80 0x80 0x01 in LEB128
        let data = vec![0x80, 0x80, 0x01];
        let mut reader = io::Cursor::new(data);
        let result = get32(&mut reader).unwrap();
        assert_eq!(result, 16384);
    }

    #[test]
    fn test_put_single_byte() {
        let mut buffer = Vec::new();
        put(&mut buffer, 42).unwrap();
        assert_eq!(buffer, vec![42]);
    }

    #[test]
    fn test_put_multi_byte() {
        let mut buffer = Vec::new();
        put(&mut buffer, 128).unwrap();
        assert_eq!(buffer, vec![0x80, 0x01]);
    }

    #[test]
    fn test_put_large_value() {
        let mut buffer = Vec::new();
        put(&mut buffer, 16384).unwrap();
        assert_eq!(buffer, vec![0x80, 0x80, 0x01]);
    }

    #[test]
    fn test_put_zero() {
        let mut buffer = Vec::new();
        put(&mut buffer, 0).unwrap();
        assert_eq!(buffer, vec![0]);
    }

    #[test]
    fn test_put_get_roundtrip() {
        for value in [0, 1, 42, 127, 128, 255, 256, 16384, 1048576] {
            let mut buffer = Vec::new();
            put(&mut buffer, value).unwrap();
            let mut reader = io::Cursor::new(buffer);
            let result = get32(&mut reader).unwrap();
            assert_eq!(result, value as u32);
        }
    }

    #[test]
    fn test_put_slice_empty() {
        let mut buffer = Vec::new();
        let slice: &[u8] = &[];
        put_slice(&mut buffer, slice).unwrap();
        // Should write length (0) as a varint
        assert_eq!(buffer, vec![0]);
    }

    #[test]
    fn test_put_slice_with_data() {
        let mut buffer = Vec::new();
        let slice = vec![1, 2, 3, 4];
        put_slice(&mut buffer, &slice).unwrap();
        // Should write length (4) then the data
        assert_eq!(buffer, vec![4, 1, 2, 3, 4]);
    }

    #[test]
    fn test_get_slice_empty() {
        let data = vec![0];
        let mut reader = io::Cursor::new(data);
        let result = get_slice(&mut reader).unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_get_slice_with_data() {
        let data = vec![4, 10, 20, 30, 40];
        let mut reader = io::Cursor::new(data);
        let result = get_slice(&mut reader).unwrap();
        assert_eq!(result, vec![10, 20, 30, 40]);
    }

    #[test]
    fn test_put_get_slice_roundtrip() {
        let original = vec![0, 1, 2, 255, 128, 64];
        let mut buffer = Vec::new();
        put_slice(&mut buffer, &original).unwrap();

        let mut reader = io::Cursor::new(buffer);
        let result = get_slice(&mut reader).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_get_slice_eof() {
        let data = vec![10]; // Says 10 bytes but doesn't provide them
        let mut reader = io::Cursor::new(data);
        let result = get_slice(&mut reader);
        assert!(result.is_err());
    }
}
