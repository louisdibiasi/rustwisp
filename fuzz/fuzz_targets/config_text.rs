#![no_main]
//! Config files and command lines: bad input is an error with a message, never a panic.

use libfuzzer_sys::fuzz_target;
use rustwisp_config::{Config, Parsed, User, parse_args};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let marker = "credential-marker-7319";
    let user = User {
        name: text.into(),
        secret: marker.into(),
    };
    assert!(!format!("{user:?}").contains(marker));
    let value = format!(":{marker}{text}");
    let error = Config::default().set("password-user", &value).unwrap_err();
    assert!(!error.contains(marker));
    let flag = format!("--password-user={value}");
    let error = parse_args(&[flag.as_str()], |_: &str| -> std::io::Result<String> {
        Err(std::io::Error::other("no files here"))
    })
    .unwrap_err();
    assert!(!error.contains(marker));
    let mut config = Config::default();
    let _ = config.load_text("fuzz.conf", text);

    let args: Vec<&str> = text.split_whitespace().collect();
    let read = |_: &str| -> std::io::Result<String> { Err(std::io::Error::other("no files here")) };
    if let Ok(Parsed::Run(c)) = parse_args(&args, read) {
        // whatever was accepted must be usable by the checks that run at startup
        let _ = c.trusted_headers.len();
    }
});
