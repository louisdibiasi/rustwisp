//! A blocking Wisp v1/v2 client.
//!
//! [`connect`] does the WebSocket upgrade and the Wisp handshake and hands back two halves: a
//! [`Handle`] that opens streams and sends data (cloneable, usable from several threads) and a
//! [`Reader`] that yields what the server sends. Sending waits for flow-control credit, so a
//! slow remote slows the sender down instead of filling memory.
//!
//! Only plain `ws://` is spoken. Put a TLS-terminating proxy in front for `wss://`.

mod url;

use holywisp_proto::wisp::{self, HEADER_LEN, ext, ptype};
use holywisp_proto::{ProtoError, base64, http, simd, webkey, ws};
use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

pub use url::WsUrl;

/// Largest DATA payload sent in one packet.
const MAX_CHUNK: usize = 64 * 1024;
/// Refuse WebSocket messages bigger than this from the server.
const MAX_MESSAGE: u64 = 16 * 1024 * 1024;
/// Credit assumed until the server says otherwise (the C server's default).
const DEFAULT_CREDIT: u32 = 128;
const MAX_UPGRADE_HEAD: usize = 8192;

/// How to connect.
#[derive(Debug, Clone)]
pub struct Options {
    /// Offer Wisp v2 (`wisp-v2` subprotocol). Off means plain v1.
    pub v2: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub connect_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            v2: true,
            username: None,
            password: None,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// What the server sent on a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Data {
        stream: u32,
        data: Vec<u8>,
    },
    /// The stream may send `remaining` more packets (stream 0 sets the default for new ones).
    Continue {
        stream: u32,
        remaining: u32,
    },
    Close {
        stream: u32,
        reason: u8,
    },
}

fn err(kind: io::ErrorKind, msg: impl Into<String>) -> io::Error {
    io::Error::new(kind, msg.into())
}

fn proto_err(e: ProtoError) -> io::Error {
    err(
        io::ErrorKind::InvalidData,
        format!("bad data from the server: {e}"),
    )
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Not secret, only unpredictable enough that frames do not repeat: seeded by the OS hasher.
fn random_u64() -> u64 {
    RandomState::new().build_hasher().finish()
}

#[derive(Debug)]
struct Credits {
    default: u32,
    streams: HashMap<u32, u32>,
    dead: bool,
}

#[derive(Debug)]
struct Writer {
    sock: TcpStream,
    scratch: Vec<u8>,
    rng: u64,
}

impl Writer {
    fn next_mask(&mut self) -> [u8; 4] {
        // xorshift64; the state is never zero
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        ((x >> 16) as u32).to_le_bytes()
    }

    /// One masked WebSocket frame whose payload is `parts` joined together.
    fn frame(&mut self, opcode: u8, parts: &[&[u8]]) -> io::Result<()> {
        let total: usize = parts.iter().map(|p| p.len()).sum();
        let mask = self.next_mask();
        let mut head = [0u8; ws::MAX_HEADER];
        let n = ws::write_header(&mut head, true, opcode, total as u64, Some(mask));
        self.scratch.clear();
        self.scratch.extend_from_slice(&head[..n]);
        for p in parts {
            self.scratch.extend_from_slice(p);
        }
        simd::unmask(&mut self.scratch[n..], mask, 0);
        self.sock.write_all(&self.scratch)
    }
}

#[derive(Debug)]
struct Shared {
    writer: Mutex<Writer>,
    credits: Mutex<Credits>,
    credit_changed: Condvar,
    next_stream: AtomicU32,
    v2: bool,
    motd: Mutex<Option<String>>,
}

impl Shared {
    fn mark_dead(&self) {
        lock(&self.credits).dead = true;
        self.credit_changed.notify_all();
    }

    fn send_packet(&self, ptype: u8, stream: u32, payload: &[u8]) -> io::Result<()> {
        let mut head = [0u8; HEADER_LEN];
        wisp::write_header(&mut head, ptype, stream);
        lock(&self.writer).frame(ws::opcode::BINARY, &[&head, payload])
    }

    fn take_credit(&self, stream: u32) -> io::Result<()> {
        let mut credits = lock(&self.credits);
        loop {
            if credits.dead {
                return Err(err(
                    io::ErrorKind::ConnectionAborted,
                    "the connection is closed",
                ));
            }
            match credits.streams.get_mut(&stream) {
                None => return Err(err(io::ErrorKind::BrokenPipe, "the stream is closed")),
                Some(n) if *n > 0 => {
                    *n -= 1;
                    return Ok(());
                }
                Some(_) => {}
            }
            credits = self
                .credit_changed
                .wait(credits)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// The sending half. Cheap to clone; every clone talks to the same connection.
#[derive(Debug, Clone)]
pub struct Handle {
    shared: Arc<Shared>,
}

impl Handle {
    /// Open a stream (`stream_type`: 1 TCP, 2 UDP, 3 terminal) and return its id.
    pub fn open(&self, stream_type: u8, host: &str, port: u16) -> io::Result<u32> {
        let id = self.shared.next_stream.fetch_add(1, Ordering::Relaxed);
        let mut payload = Vec::with_capacity(3 + host.len());
        payload.push(stream_type);
        payload.extend_from_slice(&port.to_le_bytes());
        payload.extend_from_slice(host.as_bytes());
        {
            let mut credits = lock(&self.shared.credits);
            let start = credits.default;
            credits.streams.insert(id, start);
        }
        self.shared.send_packet(ptype::CONNECT, id, &payload)?;
        Ok(id)
    }

    /// Open a TCP stream.
    pub fn open_tcp(&self, host: &str, port: u16) -> io::Result<u32> {
        self.open(wisp::stream_type::TCP, host, port)
    }

    /// Send bytes on a stream, waiting for credit when the server is behind.
    pub fn send(&self, stream: u32, data: &[u8]) -> io::Result<()> {
        for chunk in data.chunks(MAX_CHUNK) {
            self.shared.take_credit(stream)?;
            self.shared.send_packet(ptype::DATA, stream, chunk)?;
        }
        Ok(())
    }

    /// Close a stream. `wisp::close::VOLUNTARY` is the usual reason.
    pub fn close(&self, stream: u32, reason: u8) -> io::Result<()> {
        lock(&self.shared.credits).streams.remove(&stream);
        self.shared.credit_changed.notify_all();
        self.shared.send_packet(ptype::CLOSE, stream, &[reason])
    }

    /// Message of the day, when the server sent one (v2 only).
    pub fn motd(&self) -> Option<String> {
        lock(&self.shared.motd).clone()
    }

    pub fn is_v2(&self) -> bool {
        self.shared.v2
    }
}

/// The receiving half.
#[derive(Debug)]
pub struct Reader {
    sock: TcpStream,
    buf: Vec<u8>,
    start: usize,
    message: Vec<u8>,
    shared: Arc<Shared>,
}

impl Reader {
    /// Give up waiting for the server after `timeout` (`None` waits forever).
    pub fn set_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(timeout)
    }

    /// The next thing the server sent. Errors once the connection is gone.
    pub fn next_event(&mut self) -> io::Result<Event> {
        let result = self.next_event_inner();
        if let Err(e) = &result {
            // a read timeout leaves the connection usable
            if !matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) {
                self.shared.mark_dead();
            }
        }
        result
    }

    fn next_event_inner(&mut self) -> io::Result<Event> {
        loop {
            let mut msg = self.next_message()?;
            let packet = wisp::parse(&msg).map_err(proto_err)?;
            let (kind, stream) = (packet.ptype, packet.stream_id);
            match kind {
                ptype::DATA => {
                    msg.drain(..HEADER_LEN);
                    return Ok(Event::Data { stream, data: msg });
                }
                ptype::CONTINUE if packet.payload.len() >= 4 => {
                    let remaining = wisp::le32(packet.payload);
                    self.apply_continue(stream, remaining);
                    return Ok(Event::Continue { stream, remaining });
                }
                ptype::CLOSE => {
                    let reason = packet
                        .payload
                        .first()
                        .copied()
                        .unwrap_or(wisp::close::UNKNOWN);
                    lock(&self.shared.credits).streams.remove(&stream);
                    self.shared.credit_changed.notify_all();
                    return Ok(Event::Close { stream, reason });
                }
                _ => {} // INFO after the handshake and unknown types are ignored
            }
        }
    }

    fn apply_continue(&self, stream: u32, remaining: u32) {
        let mut credits = lock(&self.shared.credits);
        if stream == 0 {
            credits.default = remaining;
        } else if let Some(n) = credits.streams.get_mut(&stream) {
            *n = remaining;
        }
        drop(credits);
        self.shared.credit_changed.notify_all();
    }

    fn fill(&mut self) -> io::Result<()> {
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        } else if self.start > 1 << 20 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let mut chunk = [0u8; 64 * 1024];
        let n = self.sock.read(&mut chunk)?;
        if n == 0 {
            return Err(err(
                io::ErrorKind::UnexpectedEof,
                "the server closed the connection",
            ));
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(())
    }

    /// One whole binary message, with fragments joined and control frames answered.
    fn next_message(&mut self) -> io::Result<Vec<u8>> {
        loop {
            let head = match ws::parse_header(&self.buf[self.start..]) {
                Ok(h) => h,
                Err(ProtoError::Again) => {
                    self.fill()?;
                    continue;
                }
                Err(e) => return Err(proto_err(e)),
            };
            if head.payload_len > MAX_MESSAGE {
                return Err(err(
                    io::ErrorKind::InvalidData,
                    "the server sent an oversized frame",
                ));
            }
            let total = head.header_len + head.payload_len as usize;
            if self.buf.len() - self.start < total {
                self.fill()?;
                continue;
            }
            let from = self.start + head.header_len;
            let mut payload = self.buf[from..self.start + total].to_vec();
            self.start += total;
            if head.masked {
                simd::unmask(&mut payload, head.mask, 0);
            }
            match head.opcode {
                ws::opcode::PING => {
                    lock(&self.shared.writer).frame(ws::opcode::PONG, &[&payload])?
                }
                ws::opcode::PONG => {}
                ws::opcode::CLOSE => {
                    return Err(err(
                        io::ErrorKind::ConnectionAborted,
                        "the server closed the connection",
                    ));
                }
                op => {
                    if op != ws::opcode::CONTINUATION {
                        self.message.clear();
                    }
                    self.message.extend_from_slice(&payload);
                    if self.message.len() as u64 > MAX_MESSAGE {
                        return Err(err(
                            io::ErrorKind::InvalidData,
                            "the server sent an oversized message",
                        ));
                    }
                    if head.fin {
                        return Ok(std::mem::take(&mut self.message));
                    }
                }
            }
        }
    }
}

/// Connect to a Wisp server and finish the handshake.
pub fn connect(address: &str, options: &Options) -> io::Result<(Handle, Reader)> {
    let url = WsUrl::parse(address).map_err(|m| err(io::ErrorKind::InvalidInput, m))?;
    let sock = connect_socket(&url, options.connect_timeout)?;
    sock.set_nodelay(true)?;

    let mut raw_key = [0u8; 16];
    raw_key[..8].copy_from_slice(&random_u64().to_le_bytes());
    raw_key[8..].copy_from_slice(&random_u64().to_le_bytes());
    let key = base64::encode(&raw_key);
    let request = http::upgrade_request(
        &url.host_header(),
        url.port,
        &url.path,
        &key,
        if options.v2 { wisp::V2_PROTOCOL } else { "" },
        "",
    );
    let mut write_half = sock.try_clone()?;
    write_half.write_all(request.as_bytes())?;

    let mut read_half = sock;
    read_half.set_read_timeout(Some(options.connect_timeout))?;
    let (leftover, protocol) = read_upgrade(&mut read_half, &webkey::accept_key(&key))?;
    read_half.set_read_timeout(None)?;

    let v2 = protocol == wisp::V2_PROTOCOL;
    let shared = Arc::new(Shared {
        writer: Mutex::new(Writer {
            sock: write_half,
            scratch: Vec::new(),
            rng: random_u64() | 1,
        }),
        credits: Mutex::new(Credits {
            default: DEFAULT_CREDIT,
            streams: HashMap::new(),
            dead: false,
        }),
        credit_changed: Condvar::new(),
        next_stream: AtomicU32::new(1),
        v2,
        motd: Mutex::new(None),
    });
    let mut reader = Reader {
        sock: read_half,
        buf: leftover,
        start: 0,
        message: Vec::new(),
        shared: Arc::clone(&shared),
    };
    if v2 {
        v2_handshake(&mut reader, &shared, options)?;
    }
    Ok((Handle { shared }, reader))
}

fn connect_socket(url: &WsUrl, timeout: Duration) -> io::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let mut last = err(
        io::ErrorKind::NotFound,
        format!("no address for '{}'", url.host),
    );
    for addr in (url.host.as_str(), url.port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Read the `101` response. Returns whatever bytes followed it and the chosen subprotocol.
fn read_upgrade(sock: &mut TcpStream, expected_accept: &str) -> io::Result<(Vec<u8>, String)> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match http::parse_upgrade_response(&data, expected_accept) {
            Ok((used, protocol)) => return Ok((data.split_off(used), protocol)),
            Err(ProtoError::Again) if data.len() < MAX_UPGRADE_HEAD => {}
            Err(_) => {
                return Err(err(
                    io::ErrorKind::InvalidData,
                    "the server did not accept the WebSocket upgrade",
                ));
            }
        }
        let n = sock.read(&mut chunk)?;
        if n == 0 {
            return Err(err(
                io::ErrorKind::UnexpectedEof,
                "the server hung up during the upgrade",
            ));
        }
        data.extend_from_slice(&chunk[..n]);
    }
}

/// v2: the server speaks first with INFO; answer with ours, plus credentials when it wants them.
fn v2_handshake(reader: &mut Reader, shared: &Shared, options: &Options) -> io::Result<()> {
    let first = reader.next_message()?;
    let packet = wisp::parse(&first).map_err(proto_err)?;
    if packet.ptype != ptype::INFO {
        return Err(err(
            io::ErrorKind::InvalidData,
            "expected INFO from the server",
        ));
    }
    let info = wisp::parse_info(&packet).map_err(proto_err)?;
    *lock(&shared.motd) = info.motd.map(|m| String::from_utf8_lossy(m).into_owned());

    let mut reply = wisp::build_info(wisp::MAJOR, wisp::MINOR).to_vec();
    let mut ext_buf = Vec::new();
    if info.has_udp {
        push_extension(&mut reply, ext::UDP, &[]);
    }
    if info.has_password {
        let creds = options.username.as_deref().zip(options.password.as_deref());
        match creds {
            Some((user, pass)) => {
                ext_buf.push(u8::try_from(user.len()).map_err(|_| {
                    err(
                        io::ErrorKind::InvalidInput,
                        "the username is longer than 255 bytes",
                    )
                })?);
                let plen = u16::try_from(pass.len())
                    .map_err(|_| err(io::ErrorKind::InvalidInput, "the password is too long"))?;
                ext_buf.extend_from_slice(&plen.to_le_bytes());
                ext_buf.extend_from_slice(user.as_bytes());
                ext_buf.extend_from_slice(pass.as_bytes());
                push_extension(&mut reply, ext::PASSWORD, &ext_buf);
            }
            None if info.password_required => {
                return Err(err(
                    io::ErrorKind::PermissionDenied,
                    "the server needs a username and password",
                ));
            }
            None => {}
        }
    }
    lock(&shared.writer).frame(ws::opcode::BINARY, &[&reply])
}

fn push_extension(out: &mut Vec<u8>, id: u8, meta: &[u8]) {
    let mut tmp = vec![0u8; 5 + meta.len()];
    if let Some(n) = wisp::build_extension(&mut tmp, id, meta) {
        out.extend_from_slice(&tmp[..n]);
    }
}

#[cfg(test)]
mod tests;
