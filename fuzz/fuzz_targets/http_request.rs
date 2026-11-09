#![no_main]
//! Any bytes in: the HTTP upgrade parsers never panic, never claim to have read more than they were
//! given, and a request cannot make the server's `101` response carry extra header lines.

use rustwisp_proto::{http, webkey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((req, used)) = http::parse_request(data) {
        assert!(used <= data.len());
        let _ = (&req.method, &req.headers, req.is_websocket);
        let reply = http::upgrade_response(&req.ws_key, &req.ws_protocol);
        let bytes = reply.as_bytes();
        for (i, b) in bytes.iter().enumerate() {
            // every CR is followed by LF and every LF is preceded by CR: no injected line breaks
            if *b == b'\r' {
                assert_eq!(bytes.get(i + 1), Some(&b'\n'), "bare CR in {reply:?}");
            }
            if *b == b'\n' {
                assert!(i > 0 && bytes[i - 1] == b'\r', "bare LF in {reply:?}");
            }
        }
        assert_eq!(reply.matches("\r\n\r\n").count(), 1, "{reply:?}");
        assert!(reply.ends_with("\r\n\r\n"));
    }
    let _ = http::parse_upgrade_response(data, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = webkey::accept_key(text);
    }
});
