#![no_main]
//! Config files and command lines: bad input is an error with a message, never a panic.

use holywisp_config::{Config, Parsed, parse_args};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut config = Config::default();
    let _ = config.load_text("fuzz.conf", text);

    let args: Vec<&str> = text.split_whitespace().collect();
    let read = |_: &str| -> std::io::Result<String> { Err(std::io::Error::other("no files here")) };
    if let Ok(Parsed::Run(c)) = parse_args(&args, read) {
        // whatever was accepted must be usable by the checks that run at startup
        let _ = c.trusted_headers.len();
    }
});
