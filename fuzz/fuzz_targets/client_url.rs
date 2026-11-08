#![no_main]
//! The client's `ws://` address parser.

use holywisp_client::WsUrl;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    if let Ok(u) = WsUrl::parse(text) {
        assert!(!u.host.is_empty() && u.port != 0);
        assert!(u.path.starts_with('/'));
        let header = u.host_header();
        assert!(header.contains(&u.host));
    }
});
