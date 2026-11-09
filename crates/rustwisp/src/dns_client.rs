use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid,
    Retry,
    NotFound,
    Failed,
}

#[derive(Debug, Default)]
pub(crate) struct Answer {
    pub addrs: Vec<IpAddr>,
    pub ttl: u32,
}

pub(crate) fn server(value: &str) -> Option<SocketAddr> {
    value
        .parse()
        .ok()
        .or_else(|| {
            value
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, 53))
        })
        .or_else(|| {
            value
                .strip_prefix('[')?
                .strip_suffix(']')?
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, 53))
        })
        .filter(|s| s.port() != 0)
}

fn query(host: &str, id: u16, kind: u16) -> Result<Vec<u8>, Error> {
    if host.is_empty() || host.len() > 253 {
        return Err(Error::Invalid);
    }
    let mut out = vec![0; 12];
    out[..2].copy_from_slice(&id.to_be_bytes());
    out[2] = 1;
    out[5] = 1;
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::Invalid);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    Ok(out)
}

fn name(msg: &[u8], start: usize) -> Result<(Vec<u8>, usize), Error> {
    let mut at = start;
    let mut end = None;
    let mut out = Vec::new();
    for _ in 0..128 {
        let len = *msg.get(at).ok_or(Error::Invalid)?;
        if len & 0xc0 == 0xc0 {
            let next = *msg.get(at + 1).ok_or(Error::Invalid)?;
            end.get_or_insert(at + 2);
            at = ((len as usize & 63) << 8) | next as usize;
        } else if len == 0 {
            return Ok((out, end.unwrap_or(at + 1)));
        } else {
            if len > 63 {
                return Err(Error::Invalid);
            }
            let label = msg
                .get(at + 1..at + 1 + len as usize)
                .ok_or(Error::Invalid)?;
            if !out.is_empty() {
                out.push(b'.');
            }
            out.extend(label.iter().map(u8::to_ascii_lowercase));
            if out.len() > 253 {
                return Err(Error::Invalid);
            }
            at += 1 + len as usize;
        }
    }
    Err(Error::Invalid)
}

fn word(msg: &[u8], at: usize) -> Result<u16, Error> {
    let bytes = msg.get(at..at + 2).ok_or(Error::Invalid)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn parse(msg: &[u8], id: u16, host: &str, kind: u16) -> Result<Answer, Error> {
    if msg.len() < 12 || word(msg, 0)? != id || msg[2] & 0xf8 != 0x80 || word(msg, 4)? != 1 {
        return Err(Error::Invalid);
    }
    let (question, mut at) = name(msg, 12)?;
    if !question.eq_ignore_ascii_case(host.as_bytes())
        || word(msg, at)? != kind
        || word(msg, at + 2)? != 1
    {
        return Err(Error::Invalid);
    }
    if msg[2] & 2 != 0 {
        return Err(Error::Retry);
    }
    match msg[3] & 15 {
        0 => {}
        3 => return Err(Error::NotFound),
        _ => return Err(Error::Failed),
    }
    at += 4;
    let mut answer = Answer::default();
    for _ in 0..word(msg, 6)? {
        at = name(msg, at)?.1;
        let rr = msg.get(at..at + 10).ok_or(Error::Invalid)?;
        let typ = u16::from_be_bytes([rr[0], rr[1]]);
        let class = u16::from_be_bytes([rr[2], rr[3]]);
        let ttl = u32::from_be_bytes(rr[4..8].try_into().unwrap());
        let len = u16::from_be_bytes([rr[8], rr[9]]) as usize;
        at += 10;
        let data = msg.get(at..at + len).ok_or(Error::Invalid)?;
        let ip = match (class, typ, len) {
            (1, 1, 4) => Some(IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(data).unwrap(),
            ))),
            (1, 28, 16) => Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(data).unwrap(),
            ))),
            _ => None,
        };
        if let Some(ip) = ip
            && answer.addrs.len() < 16
        {
            answer.addrs.push(ip);
            if answer.ttl == 0 || ttl < answer.ttl {
                answer.ttl = ttl;
            }
        }
        at += len;
    }
    Ok(answer)
}

#[cfg(target_os = "linux")]
fn query_one(
    server: SocketAddr,
    host: &str,
    kind: u16,
    timeout: std::time::Duration,
) -> Result<Answer, Error> {
    use std::net::UdpSocket;
    use std::time::Instant;
    let id = crate::sys::dns_id().map_err(|_| Error::Retry)?;
    let request = query(host, id, kind)?;
    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .map_err(|_| Error::Retry)?;
    socket.connect(server).map_err(|_| Error::Retry)?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(|_| Error::Retry)?;
    socket.send(&request).map_err(|_| Error::Retry)?;
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(Error::Retry)?;
        socket
            .set_read_timeout(Some(left))
            .map_err(|_| Error::Retry)?;
        let mut buf = [0; 4096];
        let n = match socket.recv(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Retry),
        };
        match parse(&buf[..n], id, host, kind) {
            Err(Error::Invalid) => continue,
            result => return result,
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn lookup(
    servers: &[SocketAddr],
    host: &str,
    timeout: std::time::Duration,
) -> Result<Answer, Error> {
    let mut last = Error::Retry;
    for &server in servers {
        let a = query_one(server, host, 1, timeout);
        let aaaa = query_one(server, host, 28, timeout);
        let mut answer = Answer::default();
        for found in [&a, &aaaa].into_iter().flatten() {
            for &ip in &found.addrs {
                if answer.addrs.len() < 16 && !answer.addrs.contains(&ip) {
                    answer.addrs.push(ip);
                }
            }
            if !found.addrs.is_empty() && (answer.ttl == 0 || found.ttl < answer.ttl) {
                answer.ttl = found.ttl;
            }
        }
        if !answer.addrs.is_empty() {
            return Ok(answer);
        }
        if matches!((&a, &aaaa), (Err(Error::NotFound), Err(Error::NotFound))) {
            return Err(Error::NotFound);
        }
        if a.is_ok() && aaaa.is_ok() {
            return Err(Error::NotFound);
        }
        last = a.err().or_else(|| aaaa.err()).unwrap_or(Error::Failed);
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(id: u16, kind: u16) -> Vec<u8> {
        let mut msg = query("some.test", id, kind).unwrap();
        msg[2] = 0x81;
        msg[3] = 0x80;
        msg[7] = 1;
        msg.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
        msg
    }
    #[test]
    fn endpoint_and_hostname_validation() {
        for value in ["127.0.0.1", "127.0.0.1:5300", "::1", "[::1]:5300", "[::1]"] {
            assert!(server(value).is_some(), "{value}");
        }
        for value in ["host.test", "127.0.0.1:0", "[::1]:bad", "[::1"] {
            assert!(server(value).is_none(), "{value}");
        }
        for host in [
            "",
            "a..b",
            "bad/name",
            "bad name",
            &"x".repeat(64),
            &"a.".repeat(128),
        ] {
            assert!(query(host, 1, 1).is_err());
        }
    }
    #[test]
    fn compressed_answers_and_identity() {
        let msg = response(123, 1);
        let found = parse(&msg, 123, "some.test", 1).unwrap();
        assert_eq!(found.addrs, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(found.ttl, 60);
        assert_eq!(
            parse(&msg, 124, "some.test", 1).unwrap_err(),
            Error::Invalid
        );
        assert!(parse(&msg, 123, "other.test", 1).is_err());
        assert!(parse(&msg, 123, "some.test", 28).is_err());
        for end in 0..msg.len() {
            assert!(parse(&msg[..end], 123, "some.test", 1).is_err());
        }
        let mut looped = msg.clone();
        looped[12] = 0xc0;
        looped[13] = 12;
        assert!(parse(&looped, 123, "some.test", 1).is_err());
        let mut outside = msg.clone();
        outside[12] = 0xff;
        outside[13] = 0xff;
        assert!(parse(&outside, 123, "some.test", 1).is_err());
        let mut tc = msg.clone();
        tc[2] |= 2;
        assert_eq!(parse(&tc, 123, "some.test", 1).unwrap_err(), Error::Retry);
        for (rcode, error) in [(3, Error::NotFound), (2, Error::Failed)] {
            let mut failure = msg.clone();
            failure[3] = 0x80 | rcode;
            assert_eq!(parse(&failure, 123, "some.test", 1).unwrap_err(), error);
        }
    }
    #[test]
    fn address_cap_ipv6_and_minimum_ttl() {
        let mut msg = query("some.test", 1, 28).unwrap();
        msg[2] = 0x81;
        msg[7] = 20;
        for ttl in 1..=20u32 {
            msg.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1]);
            msg.extend_from_slice(&ttl.to_be_bytes());
            msg.extend_from_slice(&[0, 16]);
            msg.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        }
        let found = parse(&msg, 1, "some.test", 28).unwrap();
        assert_eq!(found.addrs.len(), 16);
        assert_eq!(found.ttl, 1);
    }
    #[test]
    fn garbage_never_panics() {
        for len in 0..256 {
            for byte in [0, 1, 63, 64, 128, 192, 255] {
                let _ = parse(&vec![byte; len], 1, "some.test", 1);
            }
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn udp_ignores_wrong_identity_and_source() {
        use std::net::UdpSocket;
        use std::time::Duration;
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let endpoint = socket.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let mut buf = [0; 512];
            let (n, peer) = socket.recv_from(&mut buf).unwrap();
            let id = word(&buf[..n], 0).unwrap();
            let mut wrong = response(id.wrapping_add(1), 1);
            socket.send_to(&wrong, peer).unwrap();
            wrong = response(id, 1);
            let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut forged = wrong.clone();
            let last = forged.len() - 1;
            forged[last] = 2;
            attacker.send_to(&forged, peer).unwrap();
            socket.send_to(&wrong, peer).unwrap();
        });
        let found = query_one(endpoint, "some.test", 1, Duration::from_secs(2)).unwrap();
        assert_eq!(found.addrs, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        responder.join().unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn silence_fails_over() {
        use std::net::UdpSocket;
        use std::time::Duration;
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let good = UdpSocket::bind("127.0.0.1:0").unwrap();
        good.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let servers = [silent.local_addr().unwrap(), good.local_addr().unwrap()];
        let responder = std::thread::spawn(move || {
            for _ in 0..2 {
                let mut buf = [0; 512];
                let (n, peer) = good.recv_from(&mut buf).unwrap();
                let msg = response(word(&buf[..n], 0).unwrap(), word(&buf[..n], n - 4).unwrap());
                good.send_to(&msg, peer).unwrap();
            }
        });
        let start = std::time::Instant::now();
        let found = lookup(&servers, "some.test", Duration::from_millis(100)).unwrap();
        assert!(!found.addrs.is_empty());
        assert!(start.elapsed() >= Duration::from_millis(180));
        assert!(start.elapsed() < Duration::from_secs(2));
        responder.join().unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn udp_negative_and_truncated_outcomes() {
        use std::net::UdpSocket;
        use std::time::Duration;
        for (rcode, truncated, expected) in [
            (3, false, Error::NotFound),
            (2, false, Error::Failed),
            (0, true, Error::Retry),
            (0, false, Error::NotFound),
        ] {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let endpoint = socket.local_addr().unwrap();
            let responder = std::thread::spawn(move || {
                for _ in 0..2 {
                    let mut buf = [0; 512];
                    let (n, peer) = socket.recv_from(&mut buf).unwrap();
                    let mut msg = buf[..n].to_vec();
                    msg[2] = if truncated { 0x83 } else { 0x81 };
                    msg[3] = 0x80 | rcode;
                    socket.send_to(&msg, peer).unwrap();
                }
            });
            assert_eq!(
                lookup(&[endpoint], "some.test", Duration::from_secs(1)).unwrap_err(),
                expected
            );
            responder.join().unwrap();
        }
    }
}
