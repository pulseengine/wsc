//! Fuzz target for varint decoding
//!
//! This target tests the LEB128 varint decoder against malformed input.
//! Varints are used extensively in WASM module parsing and signature formats.
//!
//! Security concerns:
//! - Integer overflows when decoding large values
//! - Infinite loops on malformed continuation bytes
//! - Buffer overruns when reading from truncated input
//! - Denial of service via excessive memory allocation

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

use wsc::varint;

fuzz_target!(|data: &[u8]| {
    // Test get7 (single byte varint)
    let mut cursor = Cursor::new(data);
    let _ = varint::get7(&mut cursor);

    // Test get32 (multi-byte varint up to 32 bits)
    let mut cursor = Cursor::new(data);
    let _ = varint::get32(&mut cursor);

    // Test get_slice (length-prefixed data)
    // This is particularly security-critical as it allocates memory
    // based on the decoded length
    let mut cursor = Cursor::new(data);
    let _ = varint::get_slice(&mut cursor);

    // Test multiple sequential reads (common pattern in parsers)
    let mut cursor = Cursor::new(data);
    for _ in 0..10 {
        if varint::get32(&mut cursor).is_err() {
            break;
        }
    }

    // Test alternating get7 and get32
    let mut cursor = Cursor::new(data);
    for _ in 0..5 {
        let _ = varint::get7(&mut cursor);
        let _ = varint::get32(&mut cursor);
    }
});
