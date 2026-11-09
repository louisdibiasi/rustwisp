#![no_main]
//! Any bytes in: the Wisp packet, CONNECT and INFO parsers never panic, and a CONNECT that parses
//! rebuilds into the same bytes.

use rustwisp_proto::wisp::{self, HEADER_LEN, ptype};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(p) = wisp::parse(data) else {
        return;
    };
    assert_eq!(p.payload.len(), data.len() - HEADER_LEN);
    let _ = wisp::parse_info(&p);
    let _ = wisp::type_str(p.ptype);
    let _ = wisp::close_reason_str(p.payload.first().copied().unwrap_or(0));
    if let Ok(c) = wisp::parse_connect(&p)
        && p.ptype == ptype::CONNECT
    {
        let mut out = vec![0u8; HEADER_LEN + 3 + c.host.len()];
        let n = wisp::build_connect(&mut out, p.stream_id, c.stream_type, c.port, c.host)
            .expect("buffer was sized for it");
        assert_eq!(&out[..n], data);
    }
});
