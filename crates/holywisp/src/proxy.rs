//! The conversation with an upstream proxy (SOCKS5 or HTTP CONNECT), as a state machine that does
//! no I/O. The caller peeks at what the proxy sent, calls [`Handshake::feed`], reads exactly the
//! number of bytes it reports as consumed, and acts on the [`Progress`]. Bytes the proxy sent after
//! its reply (the first bytes of the tunnel) are never consumed here.

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use holywisp_config::{ProxyKind, ProxyUrl};
use holywisp_proto::base64;
use holywisp_proto::wisp::close;

/// The configured proxy and the addresses its host resolved to at startup.
#[derive(Debug)]
pub struct Upstream {
    pub cfg: ProxyUrl,
    pub addrs: Vec<SocketAddr>,
}

impl Upstream {
    /// Resolve the proxy's host once, at startup. Failing here beats failing on every stream.
    pub fn resolve(cfg: &ProxyUrl) -> io::Result<Upstream> {
        let addrs: Vec<SocketAddr> = (cfg.host.as_str(), cfg.port)
            .to_socket_addrs()?
            .take(8)
            .collect();
        if addrs.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no address found"));
        }
        Ok(Upstream {
            cfg: cfg.clone(),
            addrs,
        })
    }
}

/// Longest HTTP response head accepted from a proxy.
const MAX_HTTP_HEAD: usize = 8192;

/// What the caller should do next.
#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    /// Nothing complete yet: wait for more bytes.
    Wait,
    /// Send these bytes to the proxy, then keep reading.
    Send(Vec<u8>),
    /// The tunnel is open.
    Done,
    /// The proxy said no, or spoke nonsense. The value is the Wisp close reason for the client.
    Fail(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Method,
    Auth,
    Reply,
    HttpHead,
}

/// One proxy conversation.
#[derive(Debug)]
pub struct Handshake {
    phase: Phase,
    acc: Vec<u8>,
    /// The SOCKS5 CONNECT request, held back until the method is agreed.
    request: Vec<u8>,
    credentials: Option<(Vec<u8>, Vec<u8>)>,
}

enum Parsed {
    Need,
    Complete(usize, Progress),
}

impl Handshake {
    /// Start a conversation to reach `host:port`. Returns the machine and the first bytes to send,
    /// or the close reason when the destination cannot be expressed to the proxy.
    pub fn new(
        kind: ProxyKind,
        credentials: Option<(&str, &str)>,
        host: &str,
        port: u16,
    ) -> Result<(Handshake, Vec<u8>), u8> {
        let target = Target::parse(host).ok_or(close::INVALID_INFO)?;
        let creds = credentials.map(|(u, p)| (u.as_bytes().to_vec(), p.as_bytes().to_vec()));
        match kind {
            ProxyKind::Socks5 => {
                // The login fields carry a one-byte length each (RFC 1929).
                if creds
                    .as_ref()
                    .is_some_and(|(u, p)| u.is_empty() || u.len() > 255 || p.len() > 255)
                {
                    return Err(close::NETWORK_ERROR);
                }
                let request = target.socks_request(port).ok_or(close::INVALID_INFO)?;
                let greeting = if creds.is_some() {
                    vec![5, 2, 0, 2]
                } else {
                    vec![5, 1, 0]
                };
                let hs = Handshake {
                    phase: Phase::Method,
                    acc: Vec::new(),
                    request,
                    credentials: creds,
                };
                Ok((hs, greeting))
            }
            ProxyKind::Http => {
                let authority = target.authority(port);
                let mut head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
                if let Some((u, p)) = creds.as_ref() {
                    let mut raw = u.clone();
                    raw.push(b':');
                    raw.extend_from_slice(p);
                    head.push_str("Proxy-Authorization: Basic ");
                    head.push_str(&base64::encode(&raw));
                    head.push_str("\r\n");
                }
                head.push_str("\r\n");
                let hs = Handshake {
                    phase: Phase::HttpHead,
                    acc: Vec::new(),
                    request: Vec::new(),
                    credentials: None,
                };
                Ok((hs, head.into_bytes()))
            }
        }
    }

    /// Look at `peeked`, the bytes currently waiting from the proxy. Returns how many of them to
    /// read off the socket and what to do next. Bytes that are not part of the reply stay unread.
    pub fn feed(&mut self, peeked: &[u8]) -> (usize, Progress) {
        let mut all = std::mem::take(&mut self.acc);
        let held = all.len();
        all.extend_from_slice(peeked);
        match self.parse(&all) {
            Parsed::Need => {
                if all.len() > MAX_HTTP_HEAD {
                    return (peeked.len(), Progress::Fail(close::NETWORK_ERROR));
                }
                self.acc = all;
                (peeked.len(), Progress::Wait)
            }
            Parsed::Complete(len, progress) => (len.saturating_sub(held), progress),
        }
    }

    fn parse(&mut self, data: &[u8]) -> Parsed {
        match self.phase {
            Phase::Method => self.parse_method(data),
            Phase::Auth => self.parse_auth(data),
            Phase::Reply => parse_socks_reply(data),
            Phase::HttpHead => parse_http_head(data),
        }
    }

    fn parse_method(&mut self, data: &[u8]) -> Parsed {
        if data.len() < 2 {
            return Parsed::Need;
        }
        let bad = || Parsed::Complete(2, Progress::Fail(close::NETWORK_ERROR));
        if data[0] != 5 {
            return bad();
        }
        match (data[1], self.credentials.as_ref()) {
            (0, _) => {
                self.phase = Phase::Reply;
                Parsed::Complete(2, Progress::Send(std::mem::take(&mut self.request)))
            }
            (2, Some((user, pass))) => {
                let mut msg = vec![1, user.len() as u8];
                msg.extend_from_slice(user);
                msg.push(pass.len() as u8);
                msg.extend_from_slice(pass);
                self.phase = Phase::Auth;
                Parsed::Complete(2, Progress::Send(msg))
            }
            _ => bad(),
        }
    }

    fn parse_auth(&mut self, data: &[u8]) -> Parsed {
        if data.len() < 2 {
            return Parsed::Need;
        }
        if data[0] != 1 || data[1] != 0 {
            return Parsed::Complete(2, Progress::Fail(close::NETWORK_ERROR));
        }
        self.phase = Phase::Reply;
        Parsed::Complete(2, Progress::Send(std::mem::take(&mut self.request)))
    }
}

fn parse_socks_reply(data: &[u8]) -> Parsed {
    if data.len() < 5 {
        return Parsed::Need;
    }
    let total = match data[3] {
        1 => 4 + 4 + 2,
        4 => 4 + 16 + 2,
        3 => 4 + 1 + usize::from(data[4]) + 2,
        _ => return Parsed::Complete(data.len(), Progress::Fail(close::NETWORK_ERROR)),
    };
    if data[0] != 5 {
        return Parsed::Complete(data.len(), Progress::Fail(close::NETWORK_ERROR));
    }
    if data[1] != 0 {
        // The reason is in the first bytes; no need to wait for the rest.
        return Parsed::Complete(data.len(), Progress::Fail(socks_reason(data[1])));
    }
    if data.len() < total {
        return Parsed::Need;
    }
    Parsed::Complete(total, Progress::Done)
}

fn socks_reason(code: u8) -> u8 {
    match code {
        2 => close::BLOCKED,
        3 | 4 => close::UNREACHABLE,
        5 => close::REFUSED,
        6 => close::NO_RESPONSE,
        _ => close::NETWORK_ERROR,
    }
}

fn parse_http_head(data: &[u8]) -> Parsed {
    let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Parsed::Need;
    };
    let head = &data[..end];
    let line = head.split(|b| *b == b'\r').next().unwrap_or(head);
    let code = std::str::from_utf8(line)
        .ok()
        .filter(|l| l.starts_with("HTTP/1."))
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse::<u16>().ok());
    let progress = match code {
        Some(200..=299) => Progress::Done,
        Some(403) => Progress::Fail(close::BLOCKED),
        Some(502 | 503 | 404) => Progress::Fail(close::UNREACHABLE),
        Some(504) => Progress::Fail(close::NO_RESPONSE),
        _ => Progress::Fail(close::NETWORK_ERROR),
    };
    Parsed::Complete(end + 4, progress)
}

/// A destination in a form that is safe to put on the wire.
enum Target {
    Ip(IpAddr),
    Name(String),
}

impl Target {
    /// Letters, digits, dots, dashes and underscores for a name; anything else that is not an IP
    /// literal is refused, so a client cannot smuggle bytes into the proxy's request.
    fn parse(host: &str) -> Option<Target> {
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Some(Target::Ip(ip));
        }
        let ok = !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
        ok.then(|| Target::Name(host.to_string()))
    }

    fn authority(&self, port: u16) -> String {
        match self {
            Target::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{port}"),
            Target::Ip(ip) => format!("{ip}:{port}"),
            Target::Name(n) => format!("{n}:{port}"),
        }
    }

    fn socks_request(&self, port: u16) -> Option<Vec<u8>> {
        let mut req = vec![5, 1, 0];
        match self {
            Target::Ip(IpAddr::V4(ip)) => {
                req.push(1);
                req.extend_from_slice(&ip.octets());
            }
            Target::Ip(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
                Some(v4) => {
                    req.push(1);
                    req.extend_from_slice(&v4.octets());
                }
                None => {
                    req.push(4);
                    req.extend_from_slice(&ip.octets());
                }
            },
            Target::Name(n) => {
                req.push(3);
                req.push(u8::try_from(n.len()).ok()?);
                req.extend_from_slice(n.as_bytes());
            }
        }
        req.extend_from_slice(&port.to_be_bytes());
        Some(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socks(creds: Option<(&str, &str)>, host: &str) -> (Handshake, Vec<u8>) {
        Handshake::new(ProxyKind::Socks5, creds, host, 443).unwrap()
    }

    #[test]
    fn socks5_without_login_for_a_name() {
        let (mut hs, first) = socks(None, "example.com");
        assert_eq!(first, [5, 1, 0]);
        let (used, p) = hs.feed(&[5, 0]);
        assert_eq!(used, 2);
        let Progress::Send(req) = p else {
            panic!("{p:?}")
        };
        assert_eq!(&req[..5], &[5, 1, 0, 3, 11]);
        assert_eq!(&req[5..16], b"example.com");
        assert_eq!(&req[16..], &443u16.to_be_bytes());
        // reply for a bound IPv4 address, followed by tunnel data that must stay unread
        let mut wire = vec![5, 0, 0, 1, 1, 2, 3, 4, 0x1f, 0x90];
        wire.extend_from_slice(b"HELLO");
        assert_eq!(hs.feed(&wire), (10, Progress::Done));
    }

    #[test]
    fn socks5_ip_literals() {
        let (mut hs, _) = socks(None, "10.1.2.3");
        let (_, Progress::Send(req)) = hs.feed(&[5, 0]) else {
            panic!()
        };
        assert_eq!(req, [5, 1, 0, 1, 10, 1, 2, 3, 0x01, 0xbb]);
        let (mut hs, _) = socks(None, "[2001:db8::1]");
        let (_, Progress::Send(req)) = hs.feed(&[5, 0]) else {
            panic!()
        };
        assert_eq!(req[3], 4);
        assert_eq!(req.len(), 4 + 16 + 2);
    }

    #[test]
    fn socks5_with_login() {
        let (mut hs, first) = socks(Some(("bob", "pw")), "h.example");
        assert_eq!(first, [5, 2, 0, 2]);
        let (_, p) = hs.feed(&[5, 2]);
        assert_eq!(
            p,
            Progress::Send(vec![1, 3, b'b', b'o', b'b', 2, b'p', b'w'])
        );
        let (used, p) = hs.feed(&[1, 0, 99]);
        assert_eq!(used, 2);
        assert!(matches!(p, Progress::Send(_)));
        let (mut bad, _) = socks(Some(("bob", "pw")), "h.example");
        bad.feed(&[5, 2]);
        assert_eq!(bad.feed(&[1, 1]).1, Progress::Fail(close::NETWORK_ERROR));
    }

    #[test]
    fn socks5_refusals_map_to_close_reasons() {
        for (code, reason) in [
            (2, close::BLOCKED),
            (3, close::UNREACHABLE),
            (4, close::UNREACHABLE),
            (5, close::REFUSED),
            (6, close::NO_RESPONSE),
            (1, close::NETWORK_ERROR),
        ] {
            let (mut hs, _) = socks(None, "x.example");
            hs.feed(&[5, 0]);
            assert_eq!(
                hs.feed(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).1,
                Progress::Fail(reason)
            );
        }
        let (mut hs, _) = socks(None, "x.example");
        assert_eq!(hs.feed(&[5, 0xff]).1, Progress::Fail(close::NETWORK_ERROR));
        let (mut hs, _) = socks(None, "x.example");
        assert_eq!(hs.feed(&[4, 0]).1, Progress::Fail(close::NETWORK_ERROR));
        // the proxy wants a login that was not configured
        let (mut hs, _) = socks(None, "x.example");
        assert_eq!(hs.feed(&[5, 2]).1, Progress::Fail(close::NETWORK_ERROR));
    }

    #[test]
    fn socks5_reply_can_arrive_one_byte_at_a_time() {
        let (mut hs, _) = socks(None, "x.example");
        let mut wire = vec![5, 0];
        wire.extend_from_slice(&[5, 0, 0, 3, 3, b'a', b'b', b'c', 0, 80]);
        let mut seen = Vec::new();
        let mut done = false;
        let mut i = 0;
        while i < wire.len() {
            // the socket only ever shows the next byte
            let (used, p) = hs.feed(&wire[i..=i]);
            assert!(used <= 1);
            i += used.max(1);
            seen.push(p);
            if matches!(seen.last(), Some(Progress::Done)) {
                done = true;
                break;
            }
        }
        assert!(done, "{seen:?}");
        assert_eq!(i, wire.len());
    }

    #[test]
    fn http_connect_request_and_ok_reply() {
        let (mut hs, first) =
            Handshake::new(ProxyKind::Http, Some(("u", "p")), "example.com", 8443).unwrap();
        let text = String::from_utf8(first).unwrap();
        assert!(
            text.starts_with("CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com:8443\r\n")
        );
        assert!(text.contains("Proxy-Authorization: Basic dTpw\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        let wire = b"HTTP/1.1 200 Connection established\r\nVia: x\r\n\r\nTUNNEL";
        assert_eq!(hs.feed(wire), (wire.len() - 6, Progress::Done));
    }

    #[test]
    fn http_reply_in_pieces_and_failures() {
        let (mut hs, _) = Handshake::new(ProxyKind::Http, None, "x.example", 80).unwrap();
        assert_eq!(hs.feed(b"HTTP/1.1 502 Bad"), (16, Progress::Wait));
        assert_eq!(
            hs.feed(b" Gateway\r\n\r\nzz"),
            (12, Progress::Fail(close::UNREACHABLE))
        );
        for (line, reason) in [
            ("403 Forbidden", close::BLOCKED),
            ("504 Gateway Timeout", close::NO_RESPONSE),
            ("407 Proxy Authentication Required", close::NETWORK_ERROR),
            ("500 Oops", close::NETWORK_ERROR),
        ] {
            let (mut hs, _) = Handshake::new(ProxyKind::Http, None, "x.example", 80).unwrap();
            let wire = format!("HTTP/1.1 {line}\r\n\r\n");
            assert_eq!(hs.feed(wire.as_bytes()).1, Progress::Fail(reason), "{line}");
        }
        let (mut hs, _) = Handshake::new(ProxyKind::Http, None, "x.example", 80).unwrap();
        assert_eq!(
            hs.feed(b"garbage\r\n\r\n").1,
            Progress::Fail(close::NETWORK_ERROR)
        );
    }

    #[test]
    fn an_endless_http_head_is_cut_off() {
        let (mut hs, _) = Handshake::new(ProxyKind::Http, None, "x.example", 80).unwrap();
        let junk = vec![b'a'; 5000];
        assert_eq!(hs.feed(&junk).1, Progress::Wait);
        assert_eq!(hs.feed(&junk).1, Progress::Fail(close::NETWORK_ERROR));
    }

    #[test]
    fn hostile_names_never_reach_the_wire() {
        for bad in [
            "a b",
            "x\r\nHost: evil",
            "h:80",
            "",
            "tab\there",
            "ünï.example",
            "a/b",
        ] {
            for kind in [ProxyKind::Socks5, ProxyKind::Http] {
                assert_eq!(
                    Handshake::new(kind, None, bad, 80).err(),
                    Some(close::INVALID_INFO),
                    "{bad:?}"
                );
            }
        }
        let long = "a".repeat(254);
        assert!(Handshake::new(ProxyKind::Socks5, None, &long, 80).is_err());
        assert!(Handshake::new(ProxyKind::Http, None, "v6.example", 80).is_ok());
    }

    #[test]
    fn socks5_logins_must_fit_a_one_byte_length() {
        let long = "x".repeat(256);
        let fits = "x".repeat(255);
        for creds in [(long.as_str(), "p"), ("u", long.as_str()), ("", "p")] {
            assert_eq!(
                Handshake::new(ProxyKind::Socks5, Some(creds), "h.example", 80).err(),
                Some(close::NETWORK_ERROR)
            );
        }
        assert!(
            Handshake::new(
                ProxyKind::Socks5,
                Some((fits.as_str(), fits.as_str())),
                "h",
                80
            )
            .is_ok()
        );
    }

    #[test]
    fn http_wraps_ipv6_in_brackets() {
        let (_, first) = Handshake::new(ProxyKind::Http, None, "[2001:db8::1]", 443).unwrap();
        let text = String::from_utf8(first).unwrap();
        assert!(text.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"));
    }
}
