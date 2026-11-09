//! The HTTP/1.1 upgrade handshake, both sides. Parsers are bounded: a request head longer than
//! [`MAX_REQUEST`] is a protocol error, and only the first [`MAX_HEADERS`] headers are kept.

use crate::{ProtoError, webkey};

pub const MAX_REQUEST: usize = 8192;
pub const MAX_HEADERS: usize = 48;
const MAX_NAME: usize = 63;
const MAX_VALUE: usize = 511;
const MAX_PATH: usize = 511;

/// A parsed request head.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub host: String,
    pub ws_key: String,
    /// First `Sec-WebSocket-Protocol` token, verbatim (it is echoed as sent).
    pub ws_protocol: String,
    /// `Upgrade: websocket`, `Connection: upgrade`, version 13, a key, and method GET.
    pub is_websocket: bool,
    pub headers: Vec<(String, String)>,
}

impl Request {
    /// Case-insensitive lookup of the first header with this name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Offset just past the blank line that ends the head, or `None` if it is not all here.
fn find_head_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn trimmed(bytes: &[u8], cap: usize) -> String {
    let s = String::from_utf8_lossy(bytes);
    let t = s.trim();
    let mut end = t.len().min(cap);
    while !t.is_char_boundary(end) {
        end -= 1;
    }
    t[..end].to_string()
}

fn token_list_has(list: &str, want: &str) -> bool {
    list.split(',').any(|t| t.trim().eq_ignore_ascii_case(want))
}

fn first_token(list: &str) -> String {
    list.trim_start()
        .chars()
        .take_while(|c| *c != ',' && !c.is_whitespace())
        .collect()
}

/// Parse a request head.
///
/// Returns the request and the number of bytes consumed (through the blank line), `Err(Again)`
/// while the head is incomplete, or `Err(Protocol)` when it is malformed or too long.
pub fn parse_request(data: &[u8]) -> Result<(Request, usize), ProtoError> {
    let head = match find_head_end(data) {
        Some(h) => h,
        None if data.len() >= MAX_REQUEST => return Err(ProtoError::Protocol),
        None => return Err(ProtoError::Again),
    };
    if head > MAX_REQUEST {
        return Err(ProtoError::Protocol);
    }
    let text = &data[..head];
    let mut lines = text.split(|&b| b == b'\n');

    let request_line = lines.next().ok_or(ProtoError::Protocol)?;
    let request_line = request_line.strip_suffix(b"\r").unwrap_or(request_line);
    let sp1 = request_line
        .iter()
        .position(|&b| b == b' ')
        .ok_or(ProtoError::Protocol)?;
    let rest = &request_line[sp1 + 1..];
    let sp2 = rest
        .iter()
        .position(|&b| b == b' ')
        .ok_or(ProtoError::Protocol)?;
    let version = &rest[sp2 + 1..];
    if !(version.starts_with(b"HTTP/1.1") || version.starts_with(b"HTTP/1.0")) {
        return Err(ProtoError::Protocol);
    }
    let mut req = Request {
        method: trimmed(&request_line[..sp1], 7),
        path: trimmed(&rest[..sp2], MAX_PATH),
        ..Request::default()
    };
    if req.method.is_empty() || req.path.is_empty() {
        return Err(ProtoError::Protocol);
    }

    let (mut upgrade, mut connection, mut version13) = (false, false, false);
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or(ProtoError::Protocol)?;
        let name = trimmed(&line[..colon], MAX_NAME);
        let value = trimmed(&line[colon + 1..], MAX_VALUE);
        match name.to_ascii_lowercase().as_str() {
            "host" => req.host = value.clone(),
            "upgrade" => upgrade = token_list_has(&value, "websocket"),
            "connection" => connection = token_list_has(&value, "upgrade"),
            "sec-websocket-key" => req.ws_key = value.clone(),
            "sec-websocket-version" => version13 = token_list_has(&value, "13"),
            "sec-websocket-protocol" => req.ws_protocol = first_token(&value),
            _ => {}
        }
        if req.headers.len() < MAX_HEADERS {
            req.headers.push((name, value));
        }
    }
    req.is_websocket =
        upgrade && connection && version13 && !req.ws_key.is_empty() && req.method == "GET";
    Ok((req, head))
}

/// The server's `101 Switching Protocols` response. `protocol` is echoed when non-empty.
pub fn upgrade_response(ws_key: &str, protocol: &str) -> String {
    let mut out = String::with_capacity(160);
    out.push_str(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
    );
    out.push_str("Sec-WebSocket-Accept: ");
    out.push_str(&webkey::accept_key(ws_key));
    out.push_str("\r\n");
    if !protocol.is_empty() {
        out.push_str("Sec-WebSocket-Protocol: ");
        out.push_str(protocol);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

/// Client side: the upgrade request. `extra` is raw `Name: value\r\n` lines appended verbatim.
pub fn upgrade_request(
    host: &str,
    port: u16,
    path: &str,
    key: &str,
    protocol: &str,
    extra: &str,
) -> String {
    let mut out = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );
    if !protocol.is_empty() {
        out.push_str("Sec-WebSocket-Protocol: ");
        out.push_str(protocol);
        out.push_str("\r\n");
    }
    out.push_str(extra);
    out.push_str("\r\n");
    out
}

/// Client side: check the `101` response. Returns bytes consumed and the echoed subprotocol.
pub fn parse_upgrade_response(
    data: &[u8],
    expected_accept: &str,
) -> Result<(usize, String), ProtoError> {
    let head = match find_head_end(data) {
        Some(h) => h,
        None if data.len() >= MAX_REQUEST => return Err(ProtoError::Protocol),
        None => return Err(ProtoError::Again),
    };
    if head < 12 || !data.starts_with(b"HTTP/1.1 101") {
        return Err(ProtoError::Protocol);
    }
    let mut accept_ok = false;
    let mut protocol = String::new();
    for line in data[..head].split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = trimmed(&line[..colon], MAX_NAME).to_ascii_lowercase();
        let value = trimmed(&line[colon + 1..], MAX_VALUE);
        match name.as_str() {
            "sec-websocket-accept" => accept_ok = value == expected_accept,
            "sec-websocket-protocol" => protocol = first_token(&value),
            _ => {}
        }
    }
    if accept_ok {
        Ok((head, protocol))
    } else {
        Err(ProtoError::Protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn good() -> String {
        format!(
            "GET /wisp/ HTTP/1.1\r\nHost: example.org\r\nUpgrade: websocket\r\n\
             Connection: keep-alive, Upgrade\r\nSec-WebSocket-Key: {KEY}\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: wisp-v2, other\r\n\r\n"
        )
    }

    #[test]
    fn parses_a_websocket_upgrade() {
        let text = good();
        let (r, n) = parse_request(text.as_bytes()).unwrap();
        assert_eq!(n, text.len());
        assert!(r.is_websocket);
        assert_eq!((r.method.as_str(), r.path.as_str()), ("GET", "/wisp/"));
        assert_eq!(r.host, "example.org");
        assert_eq!(r.ws_key, KEY);
        assert_eq!(r.ws_protocol, "wisp-v2");
        assert_eq!(r.header("HOST"), Some("example.org"));
        assert_eq!(r.header("x-missing"), None);
    }

    #[test]
    fn stops_at_the_blank_line_and_reports_consumed_bytes() {
        let mut text = good().into_bytes();
        let head = text.len();
        text.extend_from_slice(b"\x82\x05hello");
        let (_, n) = parse_request(&text).unwrap();
        assert_eq!(n, head);
    }

    #[test]
    fn plain_requests_are_not_websocket() {
        let (r, _) = parse_request(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert!(!r.is_websocket);
        assert_eq!(r.path, "/health");
        for broken in [
            good().replace("Upgrade: websocket", "Upgrade: h2c"),
            good().replace("Version: 13", "Version: 8"),
            good().replace("GET", "POST"),
            good().replace(&format!("Sec-WebSocket-Key: {KEY}\r\n"), ""),
            good().replace("keep-alive, Upgrade", "close"),
        ] {
            let (r, _) = parse_request(broken.as_bytes()).unwrap();
            assert!(!r.is_websocket, "{broken}");
        }
    }

    #[test]
    fn asks_for_more_until_the_head_is_complete() {
        let text = good();
        for n in 0..text.len() {
            assert_eq!(
                parse_request(&text.as_bytes()[..n]),
                Err(ProtoError::Again),
                "prefix {n}"
            );
        }
    }

    #[test]
    fn rejects_malformed_heads() {
        for bad in [
            "GET /\r\n\r\n",
            "GET / FTP/1.1\r\n\r\n",
            " / HTTP/1.1\r\n\r\n",
            "GET  HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nno colon here\r\n\r\n",
        ] {
            assert_eq!(
                parse_request(bad.as_bytes()),
                Err(ProtoError::Protocol),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn caps_head_size_and_header_count() {
        let big = vec![b'a'; MAX_REQUEST];
        assert_eq!(parse_request(&big), Err(ProtoError::Protocol));

        let mut text = String::from("GET / HTTP/1.1\r\n");
        for i in 0..100 {
            text.push_str(&format!("X-{i}: v\r\n"));
        }
        text.push_str("\r\n");
        let (r, _) = parse_request(text.as_bytes()).unwrap();
        assert_eq!(r.headers.len(), MAX_HEADERS);
    }

    #[test]
    fn long_values_are_truncated_not_rejected() {
        let text = format!("GET / HTTP/1.1\r\nX-Long: {}\r\n\r\n", "é".repeat(600));
        let (r, _) = parse_request(text.as_bytes()).unwrap();
        assert!(r.header("x-long").unwrap().len() <= MAX_VALUE);
    }

    #[test]
    fn accepts_http_1_0_and_bare_lf_in_the_request_line() {
        let (r, _) = parse_request(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        assert_eq!(r.method, "GET");
    }

    #[test]
    fn client_and_server_handshake_agree() {
        let req = upgrade_request("example.org", 6001, "/", KEY, "wisp-v2", "X-A: 1\r\n");
        let (parsed, n) = parse_request(req.as_bytes()).unwrap();
        assert_eq!(n, req.len());
        assert!(parsed.is_websocket);
        assert_eq!(parsed.header("x-a"), Some("1"));
        assert_eq!(parsed.host, "example.org:6001");

        let resp = upgrade_response(&parsed.ws_key, &parsed.ws_protocol);
        let accept = webkey::accept_key(KEY);
        let (used, proto) = parse_upgrade_response(resp.as_bytes(), &accept).unwrap();
        assert_eq!(used, resp.len());
        assert_eq!(proto, "wisp-v2");
    }

    #[test]
    fn upgrade_response_rejects_a_wrong_accept_or_status() {
        let resp = upgrade_response(KEY, "");
        assert_eq!(
            parse_upgrade_response(resp.as_bytes(), "wrong"),
            Err(ProtoError::Protocol)
        );
        let not_101 = resp.replace("101 Switching Protocols", "200 OK");
        assert_eq!(
            parse_upgrade_response(not_101.as_bytes(), &webkey::accept_key(KEY)),
            Err(ProtoError::Protocol)
        );
        assert_eq!(
            parse_upgrade_response(&resp.as_bytes()[..20], &webkey::accept_key(KEY)),
            Err(ProtoError::Again)
        );
    }

    /// Cheap stand-in for a fuzzer: random bytes and mutated valid heads must never panic.
    #[test]
    fn never_panics_on_garbage() {
        let mut s = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let seed = good().into_bytes();
        for _ in 0..20_000 {
            let mut data = if next() % 3 == 0 {
                (0..(next() % 400)).map(|_| next() as u8).collect()
            } else {
                seed.clone()
            };
            for _ in 0..(next() % 6) {
                if data.is_empty() {
                    break;
                }
                let i = (next() as usize) % data.len();
                data[i] = next() as u8;
            }
            if next() % 4 == 0 {
                data.truncate((next() as usize) % (data.len() + 1));
            }
            let _ = parse_request(&data);
            let _ = parse_upgrade_response(&data, "x");
        }
    }
}
