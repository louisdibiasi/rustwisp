#![no_main]
//! Any bytes in: the WebSocket header parser never panics, and a header it accepts survives being
//! written back out and parsed again.

use rustwisp_proto::ws::{self, MAX_HEADER};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(h) = ws::parse_header(data) else {
        return;
    };
    assert!(h.header_len <= data.len() && h.header_len <= MAX_HEADER);
    assert_eq!(h.header_len, ws::header_len(h.payload_len, h.masked));
    let mut out = [0u8; MAX_HEADER];
    let n = ws::write_header(
        &mut out,
        h.fin,
        h.opcode,
        h.payload_len,
        h.masked.then_some(h.mask),
    );
    let again = ws::parse_header(&out[..n]).expect("a header we wrote must parse");
    assert_eq!(again, h);
});
