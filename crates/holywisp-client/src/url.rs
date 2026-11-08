//! Parsing of `ws://host[:port][/path]` addresses.

/// Where to connect and which path to ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsUrl {
    /// Host without IPv6 brackets.
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl WsUrl {
    pub fn parse(text: &str) -> Result<WsUrl, String> {
        let rest = match text.strip_prefix("ws://") {
            Some(rest) => rest,
            None if text.starts_with("wss://") => {
                return Err("wss:// needs TLS, which this client does not speak; \
                            use ws:// or put a TLS-terminating proxy in front"
                    .into());
            }
            None => return Err(format!("expected a ws:// address, got '{text}'")),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = split_authority(authority)?;
        if host.is_empty() {
            return Err(format!("no host in '{text}'"));
        }
        Ok(WsUrl {
            host: host.to_string(),
            port,
            path,
        })
    }

    /// The host as it belongs in a `Host:` header (IPv6 addresses get brackets back).
    pub fn host_header(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }
}

fn split_authority(authority: &str) -> Result<(&str, u16), String> {
    if let Some(inner) = authority.strip_prefix('[') {
        let end = inner.find(']').ok_or("unterminated '[' in address")?;
        let tail = &inner[end + 1..];
        let port = match tail.strip_prefix(':') {
            Some(p) => parse_port(p)?,
            None if tail.is_empty() => 80,
            None => return Err(format!("junk after the IPv6 address: '{tail}'")),
        };
        return Ok((&inner[..end], port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Ok((host, parse_port(port)?)),
        None => Ok((authority, 80)),
    }
}

fn parse_port(text: &str) -> Result<u16, String> {
    text.parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("bad port '{text}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_common_shapes() {
        let u = WsUrl::parse("ws://example.com:6001/wisp/").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("example.com", 6001, "/wisp/")
        );
        let u = WsUrl::parse("ws://example.com").unwrap();
        assert_eq!((u.port, u.path.as_str()), (80, "/"));
        let u = WsUrl::parse("ws://[::1]:7000/x").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 7000));
        assert_eq!(u.host_header(), "[::1]");
        let u = WsUrl::parse("ws://[fe80::1]").unwrap();
        assert_eq!(u.port, 80);
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "http://x",
            "example.com",
            "ws://",
            "ws://:80",
            "ws://h:0",
            "ws://h:99999",
            "ws://[::1",
            "ws://[::1]x",
        ] {
            assert!(WsUrl::parse(bad).is_err(), "{bad}");
        }
        assert!(WsUrl::parse("wss://x").unwrap_err().contains("TLS"));
    }
}
