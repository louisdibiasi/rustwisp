//! Small typed values used by the configuration: host lists, port sets, CIDRs.

use std::net::IpAddr;
use std::str::FromStr;

pub const MAX_FILTER_HOSTS: usize = 256;
pub const MAX_CIDRS: usize = 64;
pub const MAX_TRUSTED_HEADERS: usize = 8;
pub const MAX_DNS_SERVERS: usize = 8;
pub const MAX_STRING: usize = 4096;

pub(crate) fn parse_bool(v: &str) -> Option<bool> {
    match v {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Lowercase, trim, and drop one trailing dot.
pub fn normalize_hostname(h: &str) -> String {
    let t = h.trim().to_ascii_lowercase();
    t.strip_suffix('.').unwrap_or(&t).to_string()
}

/// Exact names and `*.suffix` wildcards. A wildcard matches subdomains only, not the bare suffix.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostList {
    /// Entries as stored: `name`, or `.suffix` for a wildcard.
    entries: Vec<String>,
}

impl HostList {
    pub fn add(&mut self, pattern: &str) -> Result<(), String> {
        if self.entries.len() >= MAX_FILTER_HOSTS {
            return Err(format!("list full, cannot add '{pattern}'"));
        }
        let mut norm = normalize_hostname(pattern);
        if let Some(rest) = norm.strip_prefix('*') {
            norm = rest.to_string();
        }
        if norm.is_empty() || norm == "." || norm.contains(char::is_whitespace) {
            return Err(format!("invalid host '{pattern}'"));
        }
        self.entries.push(norm);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Does `host` match any entry?
    pub fn matches(&self, host: &str) -> bool {
        let host = normalize_hostname(host);
        self.entries.iter().any(|e| {
            if e.starts_with('.') {
                host.len() > e.len() && host.ends_with(e.as_str())
            } else {
                host == *e
            }
        })
    }
}

/// A set of TCP/UDP ports built from `N` or `LO-HI` specs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSet {
    bits: Box<[u64; 1024]>,
    count: u32,
}

impl Default for PortSet {
    fn default() -> Self {
        PortSet {
            bits: Box::new([0; 1024]),
            count: 0,
        }
    }
}

impl PortSet {
    pub fn add_spec(&mut self, spec: &str) -> Result<(), String> {
        let bad = || format!("bad port spec '{spec}'");
        let (lo, hi) = match spec.trim().split_once('-') {
            Some((a, b)) => (
                parse_port(a).ok_or_else(bad)?,
                parse_port(b).ok_or_else(bad)?,
            ),
            None => {
                let p = parse_port(spec).ok_or_else(bad)?;
                (p, p)
            }
        };
        let (lo, hi) = if hi < lo { (hi, lo) } else { (lo, hi) };
        for p in lo..=hi {
            if !self.contains(p) {
                self.bits[usize::from(p) >> 6] |= 1 << (p & 63);
                self.count += 1;
            }
        }
        Ok(())
    }

    pub fn contains(&self, port: u16) -> bool {
        self.bits[usize::from(port) >> 6] & (1 << (port & 63)) != 0
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn len(&self) -> usize {
        self.count as usize
    }
}

fn parse_port(s: &str) -> Option<u16> {
    let s = s.trim();
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u16>().ok().filter(|p| *p != 0)
}

/// An address with a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub bits: u8,
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => prefix_eq(&n.octets(), &a.octets(), self.bits),
            (IpAddr::V6(n), IpAddr::V6(a)) => prefix_eq(&n.octets(), &a.octets(), self.bits),
            (IpAddr::V6(n), IpAddr::V4(a)) => {
                // a v4-mapped v6 network also covers the plain v4 address
                n.to_ipv4_mapped().is_some_and(|m| {
                    self.bits >= 96 && prefix_eq(&m.octets(), &a.octets(), self.bits - 96)
                })
            }
            _ => false,
        }
    }
}

fn prefix_eq(a: &[u8], b: &[u8], bits: u8) -> bool {
    let full = usize::from(bits / 8);
    if a[..full] != b[..full] {
        return false;
    }
    let rem = bits % 8;
    rem == 0 || (a[full] ^ b[full]) >> (8 - rem) == 0
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let (addr_text, bits_text) = match text.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (text, None),
        };
        let addr: IpAddr = addr_text
            .parse()
            .map_err(|_| format!("bad address '{text}'"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits = match bits_text {
            None => max,
            Some(b) => {
                let n: u8 = b
                    .parse()
                    .map_err(|_| format!("bad prefix length in '{text}'"))?;
                if n > max {
                    return Err(format!("prefix length too large in '{text}'"));
                }
                n
            }
        };
        Ok(Cidr { addr, bits })
    }
}

/// Which protocol the upstream proxy speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Socks5,
    Http,
}

/// An upstream proxy for outbound TCP streams, from `proxy = socks5://user:pass@host:port`.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyUrl {
    pub kind: ProxyKind,
    /// Host without IPv6 brackets.
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
}

impl std::fmt::Debug for ProxyUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyUrl")
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("pass", &self.pass.as_ref().map(|_| "<hidden>"))
            .finish()
    }
}

/// Longest user name or password SOCKS5 can carry (a one-byte length).
const MAX_PROXY_CRED: usize = 255;

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

impl FromStr for ProxyUrl {
    type Err = String;

    /// Errors never repeat the input, because it may hold a password.
    fn from_str(text: &str) -> Result<Self, String> {
        let (scheme, rest) = text
            .split_once("://")
            .ok_or("expected socks5://host:port or http://host:port")?;
        let (kind, default_port) = match scheme {
            "socks5" | "socks5h" => (ProxyKind::Socks5, 1080),
            "http" => (ProxyKind::Http, 8080),
            "https" => return Err("an https:// proxy is not supported (TLS to the proxy)".into()),
            _ => return Err("proxy scheme must be socks5, socks5h or http".into()),
        };
        let authority = rest.split('/').next().unwrap_or(rest);
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let (user, pass) = match userinfo {
            None => (None, None),
            Some(info) => {
                let (u, p) = info.split_once(':').unwrap_or((info, ""));
                let u = percent_decode(u).ok_or("bad escape in the proxy user name")?;
                let p = percent_decode(p).ok_or("bad escape in the proxy password")?;
                if u.is_empty() || u.len() > MAX_PROXY_CRED || p.len() > MAX_PROXY_CRED {
                    return Err(
                        "proxy user must be 1-255 bytes and the password at most 255".into(),
                    );
                }
                (Some(u), Some(p))
            }
        };
        let (host, port) = if let Some(inner) = hostport.strip_prefix('[') {
            let end = inner
                .find(']')
                .ok_or("unterminated '[' in the proxy address")?;
            let tail = &inner[end + 1..];
            let port = match tail.strip_prefix(':') {
                Some(p) => parse_port(p).ok_or("bad proxy port")?,
                None if tail.is_empty() => default_port,
                None => return Err("junk after the proxy IPv6 address".into()),
            };
            (&inner[..end], port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h, parse_port(p).ok_or("bad proxy port")?),
                None => (hostport, default_port),
            }
        };
        if host.is_empty() || host.contains(char::is_whitespace) {
            return Err("no host in the proxy address".into());
        }
        Ok(ProxyUrl {
            kind,
            host: host.to_string(),
            port,
            user,
            pass,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bool_words() {
        for t in ["1", "true", "yes", "on"] {
            assert_eq!(parse_bool(t), Some(true));
        }
        for f in ["0", "false", "no", "off"] {
            assert_eq!(parse_bool(f), Some(false));
        }
        assert_eq!(parse_bool("maybe"), None);
        assert_eq!(parse_bool("ON"), None);
    }

    #[test]
    fn host_list_exact_and_wildcard() {
        let mut l = HostList::default();
        l.add("Example.COM.").unwrap();
        l.add("*.internal.corp").unwrap();
        l.add(".other.net").unwrap();
        assert!(l.matches("example.com"));
        assert!(l.matches("EXAMPLE.com."));
        assert!(!l.matches("www.example.com"));
        assert!(l.matches("a.internal.corp"));
        assert!(!l.matches("internal.corp"));
        assert!(l.matches("x.other.net"));
        assert!(!l.matches("notinternal.corp"));
    }

    #[test]
    fn host_list_rejects_junk_and_overflow() {
        let mut l = HostList::default();
        assert!(l.add("").is_err());
        assert!(l.add("*.").is_err());
        assert!(l.add("two words").is_err());
        for i in 0..MAX_FILTER_HOSTS {
            l.add(&format!("h{i}.test")).unwrap();
        }
        assert!(l.add("one.more").is_err());
    }

    #[test]
    fn port_set_singles_and_ranges() {
        let mut s = PortSet::default();
        s.add_spec("80").unwrap();
        s.add_spec("6000-6100").unwrap();
        s.add_spec("9100-9000").unwrap();
        assert!(s.contains(80) && s.contains(6000) && s.contains(6100) && s.contains(9050));
        assert!(!s.contains(81) && !s.contains(5999) && !s.contains(6101));
        assert_eq!(s.len(), 1 + 101 + 101);
        s.add_spec("80").unwrap();
        assert_eq!(s.len(), 1 + 101 + 101);
    }

    #[test]
    fn port_set_rejects_bad_specs() {
        let mut s = PortSet::default();
        for bad in ["", "0", "65536", "abc", "80-", "-80", "80-90-100", "8 0"] {
            assert!(s.add_spec(bad).is_err(), "{bad:?}");
        }
        assert!(s.is_empty());
        s.add_spec(" 443 ").unwrap();
        assert!(s.contains(443));
    }

    #[test]
    fn cidr_parse_and_contains() {
        let c: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(c.contains("10.255.1.1".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        let host: Cidr = "127.0.0.1".parse().unwrap();
        assert_eq!(host.bits, 32);
        assert!(host.contains("127.0.0.1".parse().unwrap()));
        assert!(!host.contains("127.0.0.2".parse().unwrap()));
        let odd: Cidr = "192.168.4.0/22".parse().unwrap();
        assert!(odd.contains("192.168.7.9".parse().unwrap()));
        assert!(!odd.contains("192.168.8.1".parse().unwrap()));
        let v6: Cidr = "fc00::/7".parse().unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("fe80::1".parse().unwrap()));
        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn cidr_rejects_bad_input() {
        for bad in [
            "",
            "10.0.0.0/33",
            "::1/129",
            "10.0.0.0/-1",
            "10.0.0.0/x",
            "nope",
            "10.0.0/8",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn proxy_url_shapes() {
        let p: ProxyUrl = "socks5://127.0.0.1:1081".parse().unwrap();
        assert_eq!(
            (p.kind, p.host.as_str(), p.port),
            (ProxyKind::Socks5, "127.0.0.1", 1081)
        );
        assert!(p.user.is_none());
        let p: ProxyUrl = "socks5h://bob:p%40ss@proxy.example".parse().unwrap();
        assert_eq!(
            (p.port, p.user.as_deref(), p.pass.as_deref()),
            (1080, Some("bob"), Some("p@ss"))
        );
        let p: ProxyUrl = "http://[::1]:3128/".parse().unwrap();
        assert_eq!(
            (p.kind, p.host.as_str(), p.port),
            (ProxyKind::Http, "::1", 3128)
        );
        let p: ProxyUrl = "http://h".parse().unwrap();
        assert_eq!(p.port, 8080);
    }

    #[test]
    fn proxy_url_errors_do_not_leak_the_password() {
        for bad in [
            "",
            "host:1080",
            "ftp://h",
            "https://h",
            "socks5://",
            "socks5://:1080",
            "socks5://h:0",
            "socks5://h:x",
            "socks5://u:%zz@h",
            "socks5://[::1",
        ] {
            assert!(bad.parse::<ProxyUrl>().is_err(), "{bad:?}");
        }
        let e = "socks5://bob:hunter2@h:0".parse::<ProxyUrl>().unwrap_err();
        assert!(!e.contains("hunter2"));
        let p: ProxyUrl = "socks5://bob:hunter2@h".parse().unwrap();
        assert!(!format!("{p:?}").contains("hunter2"));
    }
}
