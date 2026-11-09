#![no_main]
//! The upstream proxy conversation: whatever the destination name, login and replies look like, it
//! never panics, never claims to consume more than it was shown, and never puts a stray line break
//! into the HTTP request it builds.

use arbitrary::Arbitrary;
use rustwisp::proxy::{Handshake, Progress};
use rustwisp_config::ProxyKind;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Plan {
    http: bool,
    user: Option<String>,
    pass: Option<String>,
    host: String,
    port: u16,
    replies: Vec<Vec<u8>>,
}

fuzz_target!(|plan: Plan| {
    let kind = if plan.http {
        ProxyKind::Http
    } else {
        ProxyKind::Socks5
    };
    let creds = plan.user.as_deref().zip(plan.pass.as_deref());
    let Ok((mut hs, first)) = Handshake::new(kind, creds, &plan.host, plan.port) else {
        return;
    };
    assert!(!first.is_empty());
    if plan.http {
        let text = std::str::from_utf8(&first).expect("an HTTP request is text");
        assert!(text.ends_with("\r\n\r\n"));
        assert_eq!(text.matches("\r\n\r\n").count(), 1, "{text:?}");
        assert_eq!(text.matches('\n').count(), text.matches("\r\n").count());
    } else if let Some((user, pass)) = creds {
        // a SOCKS5 login is only ever built when both parts fit their one-byte length
        assert!(user.len() <= 255 && pass.len() <= 255);
    }
    for reply in &plan.replies {
        let (used, progress) = hs.feed(reply);
        assert!(used <= reply.len(), "consumed {used} of {}", reply.len());
        match progress {
            Progress::Wait => {}
            Progress::Send(bytes) => assert!(!bytes.is_empty()),
            Progress::Done | Progress::Fail(_) => break,
        }
    }
});
