#![cfg(target_os = "linux")]
#![allow(dead_code)]
//! Shared helpers for the end-to-end tests: real sockets only, no mocks. A tiny WebSocket client,
//! a started server, and a few remote peers (echo, sink, closer, UDP echo).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use rustwisp::{Server, ServerHandle, SpliceMode};
use rustwisp_config::Config;
use rustwisp_proto::wisp::{self, close, ptype, stream_type};
use rustwisp_proto::{base64, http, ws};

pub const TIMEOUT: Duration = Duration::from_secs(10);

pub fn test_config() -> Config {
    Config {
        host: "127.0.0.1".into(),
        port: 0,
        workers: 2,
        allow_loopback: true,
        allow_direct_ip: true,
        reputation_enabled: false,
        connections_limit_per_ip: 0,
        connection_window_s: 0,
        flood: rustwisp_config::FloodConfig {
            enabled: false,
            ..Config::default().flood
        },
        ..Config::default()
    }
}

pub fn start(cfg: Config) -> ServerHandle {
    start_with(cfg, SpliceMode::Auto)
}

pub fn start_with(cfg: Config, splice: SpliceMode) -> ServerHandle {
    Server::bind_with(cfg, splice)
        .expect("bind")
        .start()
        .expect("start")
}

// ------------------------------------------------------------------------------------- client

pub struct Packet {
    pub ptype: u8,
    pub sid: u32,
    pub payload: Vec<u8>,
}

pub struct Client {
    pub sock: TcpStream,
    buf: Vec<u8>,
    mask_counter: u32,
}

fn key_for(n: u32) -> String {
    let mut raw = [0u8; 16];
    raw[..4].copy_from_slice(&n.to_le_bytes());
    base64::encode(&raw)
}

impl Client {
    /// Connect and upgrade. `protocol` non-empty asks for Wisp v2.
    pub fn connect(port: u16, protocol: &str) -> Client {
        Client::connect_with(port, protocol, "")
    }

    /// Like [`Client::connect`] with extra raw header lines (each ending in CRLF).
    pub fn connect_with(port: u16, protocol: &str, extra: &str) -> Client {
        let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        sock.set_read_timeout(Some(TIMEOUT)).unwrap();
        sock.set_nodelay(true).unwrap();
        let mut c = Client {
            sock,
            buf: Vec::new(),
            mask_counter: 1,
        };
        let key = key_for(7);
        let req = http::upgrade_request("127.0.0.1", port, "/", &key, protocol, extra);
        c.sock.write_all(req.as_bytes()).unwrap();
        let accept = rustwisp_proto::webkey::accept_key(&key);
        loop {
            match http::parse_upgrade_response(&c.buf, &accept) {
                Ok((used, proto)) => {
                    assert_eq!(proto, protocol, "subprotocol is echoed verbatim");
                    c.buf.drain(..used);
                    return c;
                }
                Err(rustwisp_proto::ProtoError::Again) => c.fill(),
                Err(e) => panic!(
                    "bad upgrade response: {e:?}: {:?}",
                    String::from_utf8_lossy(&c.buf)
                ),
            }
        }
    }

    /// A v1 client that has consumed the initial CONTINUE for stream 0.
    pub fn v1(port: u16) -> Client {
        let mut c = Client::connect(port, "");
        let p = c.recv_packet();
        assert_eq!((p.ptype, p.sid), (ptype::CONTINUE, 0));
        c
    }

    fn fill(&mut self) {
        let mut tmp = [0u8; 65536];
        let n = self.sock.read(&mut tmp).expect("read");
        assert!(n > 0, "connection closed while waiting for data");
        self.buf.extend_from_slice(&tmp[..n]);
    }

    pub fn send_raw(&mut self, bytes: &[u8]) {
        self.sock.write_all(bytes).unwrap();
    }

    pub fn frame_bytes(&mut self, opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        self.mask_counter = self
            .mask_counter
            .wrapping_mul(2_654_435_761)
            .wrapping_add(12345);
        let mask = self.mask_counter.to_le_bytes();
        let mut hdr = [0u8; ws::MAX_HEADER];
        let n = ws::write_header(&mut hdr, fin, opcode, payload.len() as u64, Some(mask));
        let mut out = hdr[..n].to_vec();
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
        out
    }

    pub fn send_frame(&mut self, opcode: u8, fin: bool, payload: &[u8]) {
        let f = self.frame_bytes(opcode, fin, payload);
        self.send_raw(&f);
    }

    pub fn send_packet(&mut self, ptype: u8, sid: u32, payload: &[u8]) {
        let mut p = vec![0u8; wisp::HEADER_LEN];
        p[0] = ptype;
        p[1..5].copy_from_slice(&sid.to_le_bytes());
        p.extend_from_slice(payload);
        self.send_frame(ws::opcode::BINARY, true, &p);
    }

    pub fn connect_stream(&mut self, sid: u32, kind: u8, host: &str, port: u16) {
        let mut pl = vec![kind];
        pl.extend_from_slice(&port.to_le_bytes());
        pl.extend_from_slice(host.as_bytes());
        self.send_packet(ptype::CONNECT, sid, &pl);
    }

    pub fn tcp(&mut self, sid: u32, port: u16) {
        self.connect_stream(sid, stream_type::TCP, "127.0.0.1", port);
    }

    /// The next server frame: (opcode, payload).
    pub fn recv_frame(&mut self) -> (u8, Vec<u8>) {
        loop {
            if let Ok(h) = ws::parse_header(&self.buf) {
                let total = h.header_len + h.payload_len as usize;
                if self.buf.len() >= total {
                    assert!(!h.masked, "server frames are never masked");
                    let payload = self.buf[h.header_len..total].to_vec();
                    self.buf.drain(..total);
                    return (h.opcode, payload);
                }
            }
            self.fill();
        }
    }

    pub fn recv_packet(&mut self) -> Packet {
        let (op, payload) = self.recv_frame();
        assert_eq!(op, ws::opcode::BINARY, "expected a binary frame");
        let p = wisp::parse(&payload).expect("wisp packet");
        Packet {
            ptype: p.ptype,
            sid: p.stream_id,
            payload: p.payload.to_vec(),
        }
    }

    /// Whatever packets have already arrived, without waiting for more.
    pub fn poll_packets(&mut self) -> Vec<Packet> {
        self.sock.set_nonblocking(true).unwrap();
        let mut tmp = [0u8; 65536];
        loop {
            match self.sock.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                Err(_) => break,
            }
        }
        self.sock.set_nonblocking(false).unwrap();
        let mut out = Vec::new();
        while let Ok(h) = ws::parse_header(&self.buf) {
            let total = h.header_len + h.payload_len as usize;
            if self.buf.len() < total {
                break;
            }
            let payload = self.buf[h.header_len..total].to_vec();
            self.buf.drain(..total);
            let p = wisp::parse(&payload).expect("wisp packet");
            out.push(Packet {
                ptype: p.ptype,
                sid: p.stream_id,
                payload: p.payload.to_vec(),
            });
        }
        out
    }

    /// Skip CONTINUE packets and return the next packet of another type.
    pub fn recv_non_continue(&mut self) -> Packet {
        loop {
            let p = self.recv_packet();
            if p.ptype != ptype::CONTINUE {
                return p;
            }
        }
    }

    pub fn expect_close(&mut self, sid: u32, reason: u8) {
        let p = self.recv_non_continue();
        assert_eq!(
            p.ptype,
            ptype::CLOSE,
            "expected CLOSE, got type {}",
            p.ptype
        );
        assert_eq!(p.sid, sid);
        assert_eq!(
            p.payload,
            [reason],
            "close reason {:#x} wanted, {} got",
            reason,
            p.payload.first().map_or(0, |b| *b)
        );
    }

    /// Read DATA for `sid` until `n` bytes arrived (other streams' packets are an error).
    pub fn read_data(&mut self, sid: u32, n: usize) -> Vec<u8> {
        let mut got = Vec::with_capacity(n);
        while got.len() < n {
            let p = self.recv_non_continue();
            assert_eq!(
                p.ptype,
                ptype::DATA,
                "expected DATA, got {} (stream {}, payload {:?})",
                p.ptype,
                p.sid,
                p.payload
            );
            assert_eq!(p.sid, sid);
            got.extend_from_slice(&p.payload);
        }
        assert_eq!(got.len(), n);
        got
    }

    /// True when the server closed the TCP connection (EOF) without more data.
    pub fn expect_eof(&mut self) {
        let mut tmp = [0u8; 64];
        loop {
            match self.sock.read(&mut tmp) {
                Ok(0) => return,
                Ok(_) => {}
                Err(e) => panic!("expected EOF, got {e}"),
            }
        }
    }
}

// ------------------------------------------------------------------------------------- remote peers

/// Echoes every byte back.
pub fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            thread::spawn(move || {
                let mut r = s.try_clone().unwrap();
                let mut w = s;
                let mut buf = vec![0u8; 65536];
                while let Ok(n) = r.read(&mut buf) {
                    if n == 0 || w.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// Accepts connections and never reads from them.
pub fn sink_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut keep = Vec::new();
        for s in l.incoming().flatten() {
            keep.push(s);
        }
    });
    port
}

/// Sends `payload` to every connection, then closes it.
pub fn greeter_server(payload: Vec<u8>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let _ = s.write_all(&payload);
        }
    });
    port
}

/// Streams `total` bytes of a counter pattern as fast as the client reads, then closes.
pub fn firehose_server(total: usize) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            thread::spawn(move || {
                let mut sent = 0usize;
                let mut chunk = vec![0u8; 1 << 16];
                while sent < total {
                    let n = chunk.len().min(total - sent);
                    for (i, b) in chunk[..n].iter_mut().enumerate() {
                        *b = pattern(sent + i);
                    }
                    if s.write_all(&chunk[..n]).is_err() {
                        return;
                    }
                    sent += n;
                }
            });
        }
    });
    port
}

pub fn pattern(i: usize) -> u8 {
    (i.wrapping_mul(2_654_435_761) >> 13) as u8
}

pub fn udp_echo_server() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = s.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = s.recv_from(&mut buf) {
            let _ = s.send_to(&buf[..n], from);
        }
    });
    port
}

/// A port nothing listens on. On Linux the socket stays bound but never listens, so connecting is
/// refused and no parallel test can be handed the same port, which a closed listener would allow.
#[cfg(target_os = "linux")]
pub fn closed_port() -> u16 {
    use rustix::net::{AddressFamily, SocketAddrV4, SocketType, bind, getsockname, socket};
    let fd = socket(AddressFamily::INET, SocketType::STREAM, None).unwrap();
    bind(&fd, &SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = SocketAddrV4::try_from(getsockname(&fd).unwrap())
        .unwrap()
        .port();
    std::mem::forget(fd);
    port
}

#[cfg(not(target_os = "linux"))]
pub fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

pub fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// A simple order-sensitive checksum, so a swapped or dropped byte shows up.
pub fn checksum(data: &[u8]) -> u64 {
    let mut a: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        a ^= u64::from(b);
        a = a.wrapping_mul(0x100_0000_01b3);
    }
    a
}

/// Pseudo-random bytes from a seed (no extra dependency).
pub fn random_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

pub const REASONS: (u8, u8, u8, u8, u8) = (
    close::VOLUNTARY,
    close::REFUSED,
    close::BLOCKED,
    close::INVALID_INFO,
    close::THROTTLED,
);
