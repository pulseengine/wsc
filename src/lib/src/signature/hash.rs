use std::io::{self, Write};

#[derive(Clone, Copy)]
pub(crate) struct Hash {
    hash: hmac_sha256::Hash,
}

impl Hash {
    pub fn new() -> Self {
        Hash {
            hash: hmac_sha256::Hash::new(),
        }
    }

    pub fn update<T: AsRef<[u8]>>(&mut self, data: T) {
        self.hash.update(data);
    }

    pub fn finalize(&self) -> [u8; 32] {
        self.hash.finalize()
    }
}

impl Write for Hash {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hash.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_new() {
        let hash = Hash::new();
        let result = hash.finalize();
        // SHA-256 of empty input
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hash_update() {
        let mut hash = Hash::new();
        hash.update(b"hello");
        let result = hash.finalize();
        assert_eq!(result.len(), 32);
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn test_hash_update_multiple() {
        let mut hash1 = Hash::new();
        hash1.update(b"hello");
        hash1.update(b"world");
        let result1 = hash1.finalize();

        let mut hash2 = Hash::new();
        hash2.update(b"helloworld");
        let result2 = hash2.finalize();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_hash_as_writer() {
        let mut hash = Hash::new();
        // Use Hash as a Writer
        hash.write_all(b"test data").unwrap();
        let result = hash.finalize();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hash_flush() {
        let mut hash = Hash::new();
        hash.write_all(b"data").unwrap();
        hash.flush().unwrap();
        let result = hash.finalize();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hash_deterministic() {
        let mut hash1 = Hash::new();
        hash1.update(b"test");
        let result1 = hash1.finalize();

        let mut hash2 = Hash::new();
        hash2.update(b"test");
        let result2 = hash2.finalize();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_hash_different_inputs() {
        let mut hash1 = Hash::new();
        hash1.update(b"input1");
        let result1 = hash1.finalize();

        let mut hash2 = Hash::new();
        hash2.update(b"input2");
        let result2 = hash2.finalize();

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_hash_clone() {
        let mut hash1 = Hash::new();
        hash1.update(b"data");
        let hash2 = hash1;
        let result1 = hash1.finalize();
        let result2 = hash2.finalize();
        assert_eq!(result1, result2);
    }
}
