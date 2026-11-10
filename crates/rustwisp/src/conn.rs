//! One client connection: the HTTP upgrade, WebSocket framing, and Wisp packet dispatch.
//!
//! Client bytes are read into a per-worker buffer and complete frames are handled in place; only
//! the unfinished tail of a frame is copied into the connection.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::time::Duration;

use rustwisp_proto::wisp::{self, close, ext, ptype, stream_type};
use rustwisp_proto::{ProtoError, http, simd, ws};

use crate::auth::AuthDone;
use crate::buf::Queue;
use crate::dns::DnsDone;
use crate::filter;
use crate::link::{Link, Reg, State};
use crate::password::{self, Scheme};
use crate::reputation::{Event, Tier};
use crate::stats::Stats;
use crate::stream::{self, SState, Stream};
use crate::sys::{self, Errno, EventFlags};
use crate::worker::{Ctx, Entry, TimerKind};

/// Total bytes taken from one client in one readiness event before yielding to other connections.
const MAX_READ_PER_EVENT: usize = 1024 * 1024;

/// Multiplicative hash for the small integer keys used here.
#[derive(Default)]
pub(crate) struct IdHasher(u64);

impl Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
        }
    }
    fn write_u32(&mut self, n: u32) {
        self.0 = u64::from(n).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}

/// How a login attempt stands.
enum PwCheck {
    Ok,
    Bad,
    Pending,
}

pub(crate) type StreamMap = HashMap<u32, Stream, BuildHasherDefault<IdHasher>>;

#[derive(Debug)]
pub(crate) struct Conn {
    pub link: Link,
    pub streams: StreamMap,
    /// `pause_changed` already applied to the streams.
    applied_paused: bool,
}

impl Conn {
    pub(crate) fn accept(cx: &mut Ctx, fd: OwnedFd, peer: Option<SocketAddr>) {
        let conn_slot = cx.sh.connections.try_acquire();
        if !conn_slot {
            Stats::inc(&cx.sh.stats.refused_connection_limit);
            if !cx.sh.rejections.try_acquire() {
                Stats::inc(&cx.sh.stats.connections_total);
                return;
            }
        }
        let c = cx.cfg();
        sys::tune_tcp(&fd, c.tcp_nodelay, c.tcp_quickack, c.socket_buffer_size);
        let peer = peer.unwrap_or_else(|| SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0));
        crate::log::debug(
            "conn",
            format_args!("{peer}: accepted on worker {}", cx.index),
        );
        let ip = peer.ip().to_string();
        let stream_cap = c.max_streams_per_conn as usize;
        let timeout = c.handshake_timeout_ms.max(1);
        let handshake = Duration::from_millis(u64::from(if conn_slot {
            timeout
        } else {
            timeout.min(1000)
        }));
        let token = cx.slab.reserve();
        let mut conn = Box::new(Conn {
            link: Link {
                fd,
                reg: Reg::new(token),
                state: State::Http,
                rbuf: Vec::new(),
                need: 0,
                wbuf: Queue::new(),
                frag: None,
                is_v2: false,
                handshake_done: false,
                stream_confirm: false,
                authenticated: false,
                auth_pending: None,
                auth_confirm: false,
                paused: false,
                pause_changed: false,
                throttled: false,
                closing: false,
                violations: 0,
                conn_slot,
                reject_slot: !conn_slot,
                sigdets: HashMap::new(),
                pending_throttle_ms: 0,
                tier: Tier::Normal,
                stream_cap,
                peer,
                ip,
            },
            streams: StreamMap::default(),
            applied_paused: false,
        });
        conn.link.sync_interest(cx);
        if conn.link.closing {
            if conn_slot {
                cx.sh.connections.release();
            } else {
                cx.sh.rejections.release();
            }
            cx.slab.release(token);
            return;
        }
        Stats::inc(&cx.sh.stats.connections_total);
        Stats::inc(&cx.sh.stats.connections_active);
        if !cx.add_timer(handshake, token, 0, 0, TimerKind::Handshake) {
            conn.teardown(cx);
            cx.slab.release(token);
            return;
        }
        cx.slab.put(token, Entry::Conn(conn));
    }

    pub(crate) fn is_closing(&self) -> bool {
        self.link.closing
    }

    /// Free everything the connection holds. The descriptor closes when the value drops.
    pub(crate) fn teardown(&mut self, cx: &mut Ctx) {
        crate::log::debug("conn", format_args!("{}: closed", self.link.ip));
        let link = &mut self.link;
        for s in self.streams.values_mut() {
            stream::close_stream(link, cx, s, close::UNKNOWN, false);
        }
        self.streams.clear();
        if self.link.conn_slot {
            cx.sh.connections.release();
            self.link.conn_slot = false;
        }
        if self.link.reject_slot {
            cx.sh.rejections.release();
            self.link.reject_slot = false;
        }
        Stats::dec(&cx.sh.stats.connections_active);
    }

    /// Bring stream read interest in line with the connection's pause state.
    pub(crate) fn settle(&mut self, cx: &mut Ctx) {
        if self.link.closing {
            return;
        }
        if self.link.pending_throttle_ms > 0 {
            let wait = std::mem::take(&mut self.link.pending_throttle_ms);
            crate::log::debug(
                "conn",
                format_args!("{}: bandwidth throttle {wait} ms", self.link.ip),
            );
            self.link.throttled = true;
            self.link.sync_interest(cx);
            if !cx.add_timer(
                Duration::from_millis(wait),
                self.link.reg.token,
                0,
                0,
                TimerKind::Throttle,
            ) {
                self.link.close();
                return;
            }
        }
        let paused = self.link.reads_suspended();
        if paused == self.applied_paused {
            return;
        }
        self.applied_paused = paused;
        self.link.pause_changed = false;
        for s in self.streams.values_mut() {
            stream::set_paused(cx, s, paused);
        }
    }

    // -------------------------------------------------------------------------------- events

    pub(crate) fn on_event(&mut self, cx: &mut Ctx, flags: EventFlags) {
        if self.link.throttled
            && flags.intersects(EventFlags::RDHUP | EventFlags::HUP | EventFlags::ERR)
        {
            self.link.close();
            return;
        }
        if flags.contains(sys::OUT) {
            self.link.flush(cx);
        }
        if self.link.closing {
            return;
        }
        if flags.intersects(sys::IN | EventFlags::HUP | EventFlags::ERR) && !self.link.throttled {
            self.on_readable(cx);
        }
    }

    pub(crate) fn on_stream_event(&mut self, cx: &mut Ctx, sid: u32, flags: EventFlags) {
        let Some(s) = self.streams.get_mut(&sid) else {
            return;
        };
        stream::on_event(&mut self.link, cx, s, flags);
        if s.state == SState::Closed {
            self.streams.remove(&sid);
        }
    }

    pub(crate) fn on_resolved(&mut self, cx: &mut Ctx, done: DnsDone) {
        let Some(s) = self.streams.get_mut(&done.sid) else {
            return;
        };
        if s.serial != done.serial {
            return;
        }
        stream::on_resolved(&mut self.link, cx, s, done.addrs);
        if s.state == SState::Closed {
            self.streams.remove(&done.sid);
        }
    }

    pub(crate) fn on_timer(&mut self, cx: &mut Ctx, kind: TimerKind, sid: u32, serial: u64) {
        match kind {
            TimerKind::Handshake => {
                if !self.link.handshake_done {
                    self.link.close();
                }
            }
            TimerKind::Connect => {
                let Some(s) = self.streams.get_mut(&sid) else {
                    return;
                };
                stream::on_connect_timer(&mut self.link, cx, s, serial);
                if s.state == SState::Closed {
                    self.streams.remove(&sid);
                }
            }
            TimerKind::Throttle => {
                self.link.throttled = false;
                self.link.sync_interest(cx);
            }
        }
    }

    // -------------------------------------------------------------------------------- reading

    fn on_readable(&mut self, cx: &mut Ctx) {
        let mut total = 0;
        if self.link.state == State::HttpReply {
            return; // whatever else the client sends is ignored
        }
        while !self.link.closing && !self.link.throttled && total < MAX_READ_PER_EVENT {
            let mut rx = std::mem::take(&mut cx.rx);
            let (n, drained) = if self.link.state == State::Http || self.link.need > rx.len() {
                self.read_into_carry(cx, &mut rx)
            } else {
                self.read_into_scratch(cx, &mut rx)
            };
            cx.rx = rx;
            total += n;
            if n == 0 || drained {
                break;
            }
        }
    }

    /// The common case: carry-over bytes are copied to the front of the scratch buffer, the
    /// socket is read after them, and every complete frame is handled in place.
    fn read_into_scratch(&mut self, cx: &mut Ctx, rx: &mut [u8]) -> (usize, bool) {
        let carried = self.link.rbuf.len();
        rx[..carried].copy_from_slice(&self.link.rbuf);
        let n = match self.recv_client(&mut rx[carried..]) {
            Some(n) => n,
            None => return (0, true),
        };
        let filled = carried + n;
        let drained = filled < rx.len();
        let consumed = self.process_frames(cx, &mut rx[..filled]);
        self.link.rbuf.clear();
        if !self.link.closing {
            self.link.rbuf.extend_from_slice(&rx[consumed..filled]);
        }
        (n, drained)
    }

    /// HTTP heads and frames larger than the scratch buffer accumulate in `rbuf`.
    fn read_into_carry(&mut self, cx: &mut Ctx, rx: &mut [u8]) -> (usize, bool) {
        let want = if self.link.state == State::Http {
            rx.len().min(http::MAX_REQUEST + 1)
        } else {
            // Read no more than the frame in progress needs, so no byte of the next frame is
            // pulled into a buffer that is about to be processed in place.
            (self.link.need - self.link.rbuf.len()).clamp(1, rx.len())
        };
        let n = match self.recv_client(&mut rx[..want]) {
            Some(n) => n,
            None => return (0, true),
        };
        self.link.rbuf.extend_from_slice(&rx[..n]);
        let mut data = std::mem::take(&mut self.link.rbuf);
        let consumed = if self.link.state == State::Http {
            self.process_http(cx, &mut data)
        } else if data.len() >= self.link.need {
            self.process_frames(cx, &mut data)
        } else {
            0
        };
        if !self.link.closing {
            data.drain(..consumed);
            self.link.rbuf = data;
        }
        (n, n < want)
    }

    /// One `recv` from the client. `None` means the connection ended or nothing was available.
    fn recv_client(&mut self, buf: &mut [u8]) -> Option<usize> {
        loop {
            match sys::recv(&self.link.fd, buf) {
                Ok(0) => {
                    self.link.close();
                    return None;
                }
                Ok(n) => return Some(n),
                Err(Errno::INTR) => {}
                Err(e) if sys::is_would_block(e) => return None,
                Err(_) => {
                    self.link.close();
                    return None;
                }
            }
        }
    }

    // -------------------------------------------------------------------------------- HTTP

    fn http_reply(&mut self, cx: &Ctx, status: u16, reason: &str, ctype: &str, body: &[u8]) {
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
Cache-Control: no-store\r\nConnection: close\r\n\r\n",
            body.len()
        );
        self.link.wbuf.push(head.as_bytes());
        self.link.wbuf.push(body);
        self.link.state = State::HttpReply;
        self.link.flush(cx);
    }

    /// Handle the request head at the start of `data`. Returns bytes consumed; any bytes after the
    /// head (an eager client's first frames) are processed as WebSocket data.
    fn process_http(&mut self, cx: &mut Ctx, data: &mut [u8]) -> usize {
        let (req, used) = match http::parse_request(data) {
            Ok(r) => r,
            Err(ProtoError::Again) => return 0,
            Err(_) => {
                self.http_reply(
                    cx,
                    400,
                    "Bad Request",
                    "text/plain; charset=utf-8",
                    b"bad request\n",
                );
                return 0;
            }
        };
        if !self.link.conn_slot {
            self.http_reply(
                cx,
                503,
                "Service Unavailable",
                "text/plain; charset=utf-8",
                b"",
            );
            return used;
        }
        if !req.is_websocket {
            self.plain_reply(cx, &req);
            return used;
        }
        self.resolve_real_ip(cx, &req);
        if self.apply_reputation(cx).is_err() {
            self.http_reply(
                cx,
                403,
                "Forbidden",
                "text/plain; charset=utf-8",
                b"blocked
",
            );
            return used;
        }
        if let Some(rate) = cx.sh.conn_rate.as_ref()
            && !rate.allow(&self.link.ip, cx.sh.now_ms())
        {
            Stats::inc(&cx.sh.stats.refused_connection_rate);
            let msg = b"rate limit
";
            self.http_reply(
                cx,
                429,
                "Too Many Requests",
                "text/plain; charset=utf-8",
                msg,
            );
            return used;
        }
        let v2 = cx.cfg().enable_v2 && !req.ws_protocol.is_empty();
        if cx.cfg().password_required && !v2 {
            let msg = b"wisp-v2 with authentication required\n";
            self.http_reply(
                cx,
                426,
                "Upgrade Required",
                "text/plain; charset=utf-8",
                msg,
            );
            return used;
        }
        let protocol = if v2 { req.ws_protocol.as_str() } else { "" };
        let reply = http::upgrade_response(&req.ws_key, protocol);
        self.link.wbuf.push(reply.as_bytes());
        self.link.state = State::Ws;
        self.link.is_v2 = v2;
        if v2 {
            self.send_server_info(cx);
        } else {
            self.handshake_done(cx);
        }
        self.link.flush(cx);
        if self.link.closing {
            return used;
        }
        // Whatever followed the head is frame data.
        let rest = &mut data[used..];
        used + self.process_frames(cx, rest)
    }

    /// Apply the source's reputation tier: STRICT refuses, THROTTLE tightens the stream cap.
    fn apply_reputation(&mut self, cx: &Ctx) -> Result<(), ()> {
        let Some(rep) = cx.sh.reputation.as_ref() else {
            return Ok(());
        };
        let tier = rep.tier(rep.source_score(&self.link.ip));
        self.link.tier = tier;
        if tier == Tier::Strict {
            Stats::inc(&cx.sh.stats.refused_reputation);
            return Err(());
        }
        if tier >= Tier::Warn {
            crate::log::info(
                "reputation",
                format_args!("{}: tier {tier:?}", self.link.ip),
            );
        }
        if tier >= Tier::Throttle {
            let cap = cx.cfg().max_streams_per_conn as usize;
            self.link.stream_cap = if cap > 0 { cap.min(16) } else { 16 };
        }
        Ok(())
    }

    /// Fill `link.ip` from the trusted-proxy headers when the peer is a trusted proxy.
    fn resolve_real_ip(&mut self, cx: &Ctx, req: &http::Request) {
        let c = cx.cfg();
        if !c.parse_real_ip || c.trusted_proxies.is_empty() {
            return;
        }
        let values: Vec<&str> = c
            .trusted_headers
            .iter()
            .filter_map(|h| req.complete_header(h))
            .collect();
        let ip = filter::real_ip(self.link.peer.ip(), &c.trusted_proxies, &values);
        self.link.ip = ip.to_string();
    }

    fn plain_reply(&mut self, cx: &Ctx, req: &http::Request) {
        let c = cx.cfg();
        match req.path.as_str() {
            "/health" => {
                self.http_reply(cx, 200, "OK", "application/json", b"{\"status\":\"ok\"}\n");
            }
            "/stats" => {
                let json = cx.sh.stats.to_json();
                self.http_reply(cx, 200, "OK", "application/json", json.as_bytes());
            }
            "/" if c.serve_webclient => {
                self.http_reply(cx, 200, "OK", "text/html; charset=utf-8", &cx.sh.webclient);
            }
            _ if !c.non_ws_response.is_empty() => {
                let body = c.non_ws_response.clone();
                self.http_reply(cx, 200, "OK", "text/plain; charset=utf-8", body.as_bytes());
            }
            _ => {
                let msg = b"websocket upgrade required\n";
                self.http_reply(
                    cx,
                    426,
                    "Upgrade Required",
                    "text/plain; charset=utf-8",
                    msg,
                );
            }
        }
    }

    // -------------------------------------------------------------------------------- Wisp session

    fn send_server_info(&mut self, cx: &Ctx) {
        let c = cx.cfg();
        let mut pkt = wisp::build_info(wisp::MAJOR, wisp::MINOR).to_vec();
        let add = |pkt: &mut Vec<u8>, id: u8, meta: &[u8]| {
            let mut tmp = vec![0u8; 5 + meta.len()];
            if let Some(n) = wisp::build_extension(&mut tmp, id, meta) {
                pkt.extend_from_slice(&tmp[..n]);
            }
        };
        if c.allow_udp {
            add(&mut pkt, ext::UDP, &[]);
        }
        if !c.users.is_empty() {
            add(&mut pkt, ext::PASSWORD, &[u8::from(c.password_required)]);
        }
        if !c.motd.is_empty() {
            add(&mut pkt, ext::MOTD, c.motd.as_bytes());
        }
        self.link.send_packet(cx, &pkt);
    }

    fn handshake_done(&mut self, cx: &Ctx) {
        self.link.handshake_done = true;
        self.link.send_continue(cx, 0, cx.sh.window);
    }

    /// Check a login. Plain secrets are compared right here; hashed ones go to the auth pool and the
    /// answer arrives later through `on_auth`.
    fn check_password(&mut self, cx: &Ctx, user: &[u8], pass: &[u8]) -> PwCheck {
        let Ok(user) = std::str::from_utf8(user) else {
            return PwCheck::Bad;
        };
        let users = &cx.cfg().users;
        let (secret, force_fail) = match users.iter().find(|u| u.name == user) {
            Some(u) => (u.secret.as_str(), false),
            // An unknown name still costs a hash when hashes are in use, so the time it takes does
            // not reveal which names exist.
            None => match users
                .iter()
                .find(|u| password::scheme(&u.secret) != Ok(Scheme::Plain))
            {
                Some(h) => (h.secret.as_str(), true),
                None => return PwCheck::Bad,
            },
        };
        if password::scheme(secret) == Ok(Scheme::Plain) {
            let ok = !force_fail && password::verify_plain(secret, pass);
            return if ok { PwCheck::Ok } else { PwCheck::Bad };
        }
        match cx
            .sh
            .auth
            .submit(&cx.mailbox, self.link.reg.token, secret, pass, force_fail)
        {
            Some(id) => {
                self.link.auth_pending = Some(id);
                PwCheck::Pending
            }
            None => PwCheck::Bad,
        }
    }

    fn auth_failed(&mut self, cx: &Ctx, reason: u8) {
        Stats::inc(&cx.sh.stats.auth_failures);
        self.link.rep_source(cx, Event::AuthFailure);
        self.link.send_close(cx, 0, reason);
        self.link.close();
    }

    fn handle_info(&mut self, cx: &Ctx, p: &wisp::Packet<'_>) {
        let c = cx.cfg();
        let info = match wisp::parse_info(p) {
            Ok(i) if i.major == wisp::MAJOR => i,
            _ => {
                self.link.send_close(cx, 0, close::INCOMPATIBLE);
                self.link.close();
                return;
            }
        };
        if !c.users.is_empty()
            && info.has_password
            && let (Some(u), Some(pw)) = (info.user, info.pass)
        {
            match self.check_password(cx, u, pw) {
                PwCheck::Ok => self.link.authenticated = true,
                PwCheck::Bad => return self.auth_failed(cx, close::AUTH_BAD_PASSWORD),
                PwCheck::Pending => {
                    self.link.auth_confirm = info.has_stream_confirm;
                    return;
                }
            }
        }
        self.finish_info(cx, info.has_stream_confirm);
    }

    fn finish_info(&mut self, cx: &Ctx, stream_confirm: bool) {
        if cx.cfg().password_required && !self.link.authenticated {
            return self.auth_failed(cx, close::AUTH_REQUIRED);
        }
        self.link.stream_confirm = stream_confirm;
        self.handshake_done(cx);
    }

    /// A hashed password finished checking.
    pub(crate) fn on_auth(&mut self, cx: &mut Ctx, done: AuthDone) {
        if self.link.auth_pending != Some(done.id) || self.link.closing {
            return;
        }
        self.link.auth_pending = None;
        if !done.ok {
            return self.auth_failed(cx, close::AUTH_BAD_PASSWORD);
        }
        self.link.authenticated = true;
        let confirm = self.link.auth_confirm;
        self.finish_info(cx, confirm);
    }

    fn handle_connect(&mut self, cx: &mut Ctx, p: &wisp::Packet<'_>) {
        // A CLOSE for stream 0 would end the whole connection, so a CONNECT on it gets no reply.
        if p.stream_id == 0 {
            return;
        }
        let sid = p.stream_id;
        let req = match wisp::parse_connect(p) {
            Ok(r)
                if !r.host.is_empty()
                    && r.host.len()
                        <= if cfg!(feature = "twisp") && r.stream_type == stream_type::TERM {
                            4096
                        } else {
                            255
                        }
                    && !r.host.contains(&0) =>
            {
                r
            }
            _ => {
                self.link.send_close(cx, sid, close::INVALID_INFO);
                return;
            }
        };
        let Ok(host) = std::str::from_utf8(req.host) else {
            self.link.send_close(cx, sid, close::INVALID_INFO);
            return;
        };
        if self.streams.contains_key(&sid) {
            self.link.send_close(cx, sid, close::INVALID_INFO);
            return;
        }
        if self.link.stream_cap > 0 && self.streams.len() >= self.link.stream_cap {
            self.link.violation(cx);
            self.link.send_close(cx, sid, close::THROTTLED);
            return;
        }
        let c = cx.cfg();
        if req.stream_type == stream_type::TERM {
            #[cfg(feature = "twisp")]
            if c.enable_twisp && self.link.is_v2 && self.link.authenticated {
                stream::open_terminal(self, cx, sid, host);
                return;
            }
            self.link.rep_source(cx, Event::TwispNoAuth);
            crate::log::warn(
                "twisp",
                format_args!("{}: terminal stream refused", self.link.ip),
            );
            self.link.send_close(cx, sid, close::BLOCKED);
            return;
        }
        if (req.stream_type == stream_type::TCP && !c.allow_tcp)
            || (req.stream_type == stream_type::UDP && !c.allow_udp)
        {
            self.link.send_close(cx, sid, close::BLOCKED);
            return;
        }
        if req.stream_type != stream_type::TCP && req.stream_type != stream_type::UDP {
            self.link.send_close(cx, sid, close::INVALID_INFO);
            return;
        }
        if let Some(rate) = cx.sh.per_source.as_ref()
            && !rate.allow(&self.link.ip, cx.sh.now_ms())
        {
            Stats::inc(&cx.sh.stats.throttled_source);
            self.link.rep_source(cx, Event::BurstRate);
            self.link.violation(cx);
            if self.link.closing {
                return;
            }
            self.link.send_close(cx, sid, close::THROTTLED);
            return;
        }
        stream::open(self, cx, sid, req.stream_type, host, req.port);
    }

    fn handle_message(&mut self, cx: &mut Ctx, data: &[u8]) {
        let Ok(p) = wisp::parse(data) else {
            return; // a runt packet is ignored, as other servers do
        };
        if self.link.is_v2 && !self.link.handshake_done {
            if p.ptype == ptype::INFO && p.stream_id == 0 {
                if self.link.auth_pending.is_none() {
                    self.handle_info(cx, &p);
                }
            } else if p.ptype == ptype::CLOSE && p.stream_id == 0 {
                self.link.close();
            }
            return;
        }
        match p.ptype {
            ptype::DATA => {
                let Some(s) = self.streams.get_mut(&p.stream_id) else {
                    return; // raced with our CLOSE
                };
                Stats::add(&cx.sh.stats.bytes_in, p.payload.len() as u64);
                self.link.charge_bandwidth(cx, p.payload.len());
                stream::on_data(&mut self.link, cx, s, p.payload);
                if s.state == SState::Closed {
                    self.streams.remove(&p.stream_id);
                }
            }
            ptype::CONNECT => self.handle_connect(cx, &p),
            #[cfg(feature = "twisp")]
            wisp::TWISP_RESIZE if p.payload.len() >= 4 => {
                if let Some(s) = self.streams.get(&p.stream_id)
                    && s.terminal.is_some()
                    && let Some(fd) = s.fd.as_ref()
                {
                    sys::terminal_resize(
                        fd,
                        u16::from_le_bytes([p.payload[0], p.payload[1]]),
                        u16::from_le_bytes([p.payload[2], p.payload[3]]),
                    );
                }
            }
            ptype::CLOSE => {
                if p.stream_id == 0 {
                    self.link.close();
                    return;
                }
                if let Some(mut s) = self.streams.remove(&p.stream_id) {
                    stream::close_stream(&mut self.link, cx, &mut s, close::VOLUNTARY, false);
                }
            }
            _ => {}
        }
    }

    // -------------------------------------------------------------------------------- WebSocket

    fn ws_fail(&mut self, cx: &Ctx, code: u16) {
        self.link
            .send_frame(cx, ws::opcode::CLOSE, &[&code.to_be_bytes()]);
        self.link.close();
    }

    /// Handle every complete frame at the front of `data`; returns how many bytes that was.
    /// `data` is unmasked in place. Sets `link.need` when a frame is waiting for more bytes.
    fn process_frames(&mut self, cx: &mut Ctx, data: &mut [u8]) -> usize {
        let max = u64::from(cx.cfg().max_message_size);
        self.link.need = 0;
        let mut pos = 0;
        while !self.link.closing {
            let rest = &mut data[pos..];
            let h = match ws::parse_header(rest) {
                Ok(h) => h,
                Err(ProtoError::Again) => break,
                Err(_) => {
                    self.ws_fail(cx, 1002);
                    break;
                }
            };
            if !h.masked {
                self.ws_fail(cx, 1002);
                break;
            }
            if h.payload_len > max {
                self.ws_fail(cx, 1009);
                break;
            }
            let total = h.header_len + h.payload_len as usize;
            if rest.len() < total {
                self.link.need = total;
                break;
            }
            let payload = &mut rest[h.header_len..total];
            simd::unmask(payload, h.mask, 0);
            self.handle_frame(cx, h.opcode, h.fin, payload);
            pos += total;
        }
        pos
    }

    fn handle_frame(&mut self, cx: &mut Ctx, opcode: u8, fin: bool, payload: &[u8]) {
        match opcode {
            ws::opcode::BINARY => {
                if self.link.frag.is_some() {
                    return self.ws_fail(cx, 1002);
                }
                if fin {
                    self.handle_message(cx, payload);
                } else {
                    self.link.frag = Some(payload.to_vec());
                }
            }
            ws::opcode::CONTINUATION => {
                let max = cx.cfg().max_message_size as usize;
                let Some(frag) = self.link.frag.as_mut() else {
                    return self.ws_fail(cx, 1002);
                };
                if frag.len() + payload.len() > max {
                    return self.ws_fail(cx, 1009);
                }
                frag.extend_from_slice(payload);
                if fin {
                    let msg = self.link.frag.take().unwrap_or_default();
                    self.handle_message(cx, &msg);
                }
            }
            ws::opcode::PING => self.link.send_frame(cx, ws::opcode::PONG, &[payload]),
            ws::opcode::PONG => {}
            ws::opcode::CLOSE => {
                if payload.len() == 1 {
                    return self.ws_fail(cx, 1002);
                }
                let code = if payload.len() >= 2 {
                    let code = u16::from_be_bytes([payload[0], payload[1]]);
                    if !matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999) {
                        return self.ws_fail(cx, 1002);
                    }
                    if std::str::from_utf8(&payload[2..]).is_err() {
                        return self.ws_fail(cx, 1007);
                    }
                    code
                } else {
                    1000
                };
                self.ws_fail(cx, code);
            }
            ws::opcode::TEXT => self.ws_fail(cx, 1003),
            _ => self.ws_fail(cx, 1002),
        }
    }
}
